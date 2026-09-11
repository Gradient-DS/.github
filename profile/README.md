## Gradient Data Science

We build AI systems for Dutch public-sector and enterprise organisations:
retrieval, document processing and assistants that run on infrastructure our
clients control, in the Netherlands.

### What we work on

- **[soev.ai](https://soev.ai)** — our AI platform for government organisations.
  Chat, document search and agents over an organisation's own data, deployed per
  tenant, each with its own database and vector store.
- **Document intelligence** — ingestion, extraction and retrieval pipelines for
  archives that were never built to be searched.
- **Open work** — some of what we build is public here, including
  [warren](https://github.com/Gradient-DS/warren), a message-driven document
  processing framework whose workers select their own work off a queue.

### How we build

Sovereignty is a requirement, not a feature: our deployments run on European
infrastructure, and a tenant's data stays in that tenant's own stores.

Every repository here runs the same security gates on each pull request —
dependency, secret, container and static analysis — plus a runtime gate that
drives an application's own API against a hostile corpus while a syscall sensor
watches for egress and sensitive reads. A change that makes an application
reach somewhere it should not does not merge.

### Get in touch

We are usually hiring engineers who like this kind of problem.

- [gradient-ds.com](https://gradient-ds.com)
- [lex@gradient-ds.com](mailto:lex@gradient-ds.com)
- Amsterdam, Netherlands
