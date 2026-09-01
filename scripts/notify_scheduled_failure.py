"""Build the issue a failed scheduled security scan opens.

A stable title lets `gh issue list --search` find the existing issue, so weekly
failures append to one thread instead of opening a new issue every Monday.
"""
from __future__ import annotations

TITLE_PREFIX = "Scheduled security scan failing"


def issue_title(repo: str) -> str:
    return f"{TITLE_PREFIX}: {repo}"


def issue_body(repo: str, run_url: str, failed_jobs: list[str]) -> str:
    jobs = "\n".join(f"- `{j}`" for j in failed_jobs) if failed_jobs else "- (see run)"
    return (
        f"The weekly security scan for **{repo}** failed.\n\n"
        f"Failed jobs:\n{jobs}\n\n"
        f"Run: {run_url}\n\n"
        "This is a scheduled run, so it blocks no PR. It still means a new "
        "advisory landed against code already on the branch. Per the exception "
        "policy: upgrade if a fix exists, otherwise replace the package, "
        "otherwise request an exception from @Gradient-DS/security.\n"
    )
