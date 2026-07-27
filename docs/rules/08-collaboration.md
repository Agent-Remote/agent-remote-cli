# 08 Collaboration

Use short-lived `feature/`, `fix/`, `refactor/`, `chore/`, or `docs/` branches with lowercase descriptive topics.

Commits follow Conventional Commits: `type(scope): subject` or `type: subject`. Allowed types are `feat`, `fix`, `refactor`, `chore`, `docs`, `perf`, `test`, `build`, `ci`, and `style`. Use a concise lowercase English imperative subject, no trailing period, and at most 120 characters.

Install hooks with `scripts/install-githooks.sh`. `pre-commit` and `pre-push` run the full quality gate; `commit-msg` validates the subject.

Pull requests must describe CLI compatibility, platform impact, server contract assumptions, security-sensitive state changes, and test coverage. Do not bypass hooks or weaken CI to merge a change.
