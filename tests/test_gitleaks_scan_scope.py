"""The gitleaks scan must depend on the ref under test, and on nothing else.

`gitleaks git` runs `git log -p -U0 <log-opts>` and defaults those options to
`--full-history --all`. Combined with `fetch-depth: 0` in the workflow — which
fetches every branch — that made a PR's gate depend on every other branch in
the repository: a secret on somebody else's unmerged branch failed an unrelated
PR, and no exception could durably suppress it, because a gitleaks fingerprint
contains a commit SHA and changes the moment that branch is squash-merged.

Two properties are tested here, and they pull in opposite directions:

  * scoped   — commits reachable only from another ref must NOT be scanned;
  * complete — everything reachable from HEAD must STILL be scanned, including
               root commits and content deleted long ago. The bug must not be
               "fixed" by degrading the scan to the PR diff.
"""
from __future__ import annotations

import random
import shutil
import string
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security-source.yml"
GITLEAKS = shutil.which("gitleaks")

needs_gitleaks = pytest.mark.skipif(
    GITLEAKS is None,
    reason="gitleaks binary not on PATH; CI installs it for this test",
)


def _secrets_steps() -> list[dict]:
    # `on` is parsed as the boolean True by YAML 1.1, which is why this reads
    # jobs directly rather than validating the whole document.
    wf = yaml.safe_load(WORKFLOW.read_text())
    return wf["jobs"]["secrets"]["steps"]


def _gitleaks_step() -> dict:
    """The step in the `secrets` job that actually runs the scan."""
    scans = [s for s in _secrets_steps() if "gitleaks git" in (s.get("run") or "")]
    assert len(scans) == 1, f"expected exactly one gitleaks scan step, found {len(scans)}"
    return scans[0]


def _repo_checkout_step() -> dict:
    """The checkout of the CALLER's repository — the first checkout in the job.
    The later one fetches the shared tooling into a subdirectory."""
    checkouts = [
        s for s in _secrets_steps()
        if str(s.get("uses", "")).startswith("actions/checkout")
        and "repository" not in (s.get("with") or {})
    ]
    assert len(checkouts) == 1, f"expected one caller checkout, found {len(checkouts)}"
    return checkouts[0]


def _script_lines(step: dict) -> list[str]:
    """The step's run script with comment and blank lines dropped."""
    return [
        ln for ln in step["run"].splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


def test_scan_step_pins_the_scan_to_head():
    """Regression guard: dropping --log-opts silently restores `--all`, and
    the failure mode is a red gate on a branch the PR author does not own."""
    command = " ".join(_script_lines(_gitleaks_step()))
    assert "--log-opts=" in command, (
        "gitleaks git defaults its log options to `--full-history --all`; "
        "without an explicit --log-opts the scan covers every fetched ref"
    )
    assert "HEAD" in command, "--log-opts must scope the scan to HEAD"


def test_scan_step_does_not_reintroduce_all_refs():
    command = " ".join(_script_lines(_gitleaks_step()))
    assert "--all" not in command


def test_caller_checkout_keeps_full_history():
    """The other half of the scoping fix, and the easier one to break.

    `--log-opts=--full-history HEAD` limits which REFS are scanned; it is
    fetch-depth: 0 that makes the commits behind HEAD present at all. A
    shallow checkout would leave the flag in place and still reduce the scan
    to the tip commit — a gate that passes because it looked at almost
    nothing. Neither guard is sufficient alone, so both are asserted."""
    step = _repo_checkout_step()
    assert (step.get("with") or {}).get("fetch-depth") == 0, (
        "the secrets job must check out full history; without fetch-depth: 0 "
        "the scan silently shrinks to the tip commit"
    )


def test_scan_step_still_fails_the_job_on_a_finding():
    """The scoping change must not quietly turn the gate advisory."""
    command = " ".join(_script_lines(_gitleaks_step()))
    assert "--exit-code 1" in command


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=repo, check=True, capture_output=True,
    )


def _secret(seed: int) -> str:
    """A token-shaped string gitleaks recognises. Generated, never a literal,
    so this file does not itself become a finding."""
    rnd = random.Random(seed)
    body = "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(36))
    return "ghp_" + body


def _commit_secret(repo: Path, name: str, seed: int) -> None:
    (repo / name).write_text(f'token = "{_secret(seed)}"\n')
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", f"add {name}")


def _scan(repo: Path, empty_ignore: Path, *extra: str) -> int:
    """Number of leaks gitleaks reports (via its exit code)."""
    proc = subprocess.run(
        [GITLEAKS, "git", ".", "--no-banner", "--redact", "--exit-code", "1",
         "--report-format", "json", "--report-path", str(repo / "report.json"),
         "-i", str(empty_ignore), *extra],
        cwd=repo, capture_output=True, text=True,
    )
    assert proc.returncode in (0, 1), proc.stderr
    import json
    return len(json.loads((repo / "report.json").read_text()) or [])


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo whose HEAD branch holds one secret in a since-deleted file, with
    a second secret living only on an unrelated branch."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main", ".")
    _commit_secret(r, "old-config.txt", seed=1)      # root commit
    (r / "old-config.txt").unlink()                  # deleted, but still in history
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "remove the config")

    _git(r, "checkout", "-q", "-b", "someone-elses-branch")
    _commit_secret(r, "their-config.txt", seed=2)
    _git(r, "checkout", "-q", "main")
    return r


@needs_gitleaks
def test_default_log_opts_leak_across_branches(repo, tmp_path):
    """Characterises the bug: the default scan sees the other branch."""
    empty = tmp_path / "empty.gitleaksignore"
    empty.write_text("")
    assert _scan(repo, empty) == 2


@needs_gitleaks
def test_head_scope_excludes_other_branches(repo, tmp_path):
    empty = tmp_path / "empty.gitleaksignore"
    empty.write_text("")
    assert _scan(repo, empty, "--log-opts=--full-history HEAD") == 1


@needs_gitleaks
def test_head_scope_still_scans_deleted_history(repo, tmp_path):
    """The one finding left is the root-commit secret in a file that no longer
    exists — proof the fix scopes the ref set without shrinking to the diff."""
    empty = tmp_path / "empty.gitleaksignore"
    empty.write_text("")
    _scan(repo, empty, "--log-opts=--full-history HEAD")
    import json
    findings = json.loads((repo / "report.json").read_text())
    assert [f["File"] for f in findings] == ["old-config.txt"]
