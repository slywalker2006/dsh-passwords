# Community Checklist

社区规范清单 / Community operating checklist

This checklist records the current community surface and turns recurring repository patterns into a lightweight maintenance process. It is based on the repository at `main` and the public GitHub history reviewed on 2026-09-05.

## Baseline scan / 扫描基线

- [x] Local source, package metadata, README files, compatibility matrix, changelog, CI workflow, tests, installers, Docker files, and Git history reviewed.
- [x] GitHub Issues reviewed: 18 total, all currently closed; recurring topics include proxy response framing, remote file download, npm-prefix installation, settings over HTTPS, multi-user workspace/session grants, archived sessions, WebSocket allowlists, DSH compatibility, large uploads, Agent preset permissions, and subuser message synchronization.
- [x] GitHub Pull Requests reviewed: 5 total, all closed and merged. Contributions came through forks and generally included a problem statement, implementation notes, validation, and an issue reference.
- [x] GitHub Discussions reviewed: 3 public threads. They cover chat-entry visibility, cross-user workspace/session isolation, and workspace cleanup ideas. Discussion #27 was open at the time of review.
- [x] Forks reviewed: 11 public forks. Forks include compatibility fixes, UI changes, archive handling, and downstream feature experiments. Fork behavior must not be treated as an endorsement or as a supported distribution.
- [x] GitHub Actions workflow reviewed: CI runs `npm ci`, `npm run build`, and `npm test` on Node 22 and Node 24 for pushes and pull requests targeting `main`.

## Community entry points / 社区入口

- Bug: use the [bug report template](../.github/ISSUE_TEMPLATE/bug_report.md).
- Feature: use the [feature request template](../.github/ISSUE_TEMPLATE/feature_request.md).
- Security: use a private security advisory or private maintainer contact; the public [security template](../.github/ISSUE_TEMPLATE/security_report.md) must not contain an exploitable proof of concept.
- Question, deployment experience, or architecture discussion: use GitHub Discussions.
- Code or documentation: open a pull request using [`PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md).
- DSH core behavior: first check the [official DeepSeek Harness repository](https://github.com/deepseek-ai/deepseek-harness).
- Third-party plugin behavior: first check the plugin's own repository. Include evidence showing that dsh-passwords changed the request, response, authentication, or routing before treating it as a dsh-passwords defect.

## Reporter checklist / 报告者清单

- [ ] Search existing Issues, Discussions, PRs, Releases, and the compatibility matrix.
- [ ] State dsh-passwords version, DSH version and source, Node.js version, OS/architecture, install method, browser, proxy/TLS topology, and relevant plugin versions.
- [ ] State whether the affected account is the owner, a subuser, or both.
- [ ] Provide exact reproduction steps, expected result, actual result, HTTP status/error code, and the smallest useful sanitized log excerpt.
- [ ] For permission reports, provide a before/after matrix: actor, resource, intended operation, observed operation, and result.
- [ ] For compatibility reports, identify the DSH wire or bundle shape, not only a version string.
- [ ] For intermittent reports, include refresh/reconnect behavior, timing, network conditions, archive/delete state, and whether a clean install changes the result.
- [ ] Remove passwords, tokens, API keys, cookies, JWTs, `.env` values, setup keys, SSH credentials, private URLs, personal data, and production identifiers.

## Maintainer triage checklist / 维护者分流清单

### 1. Classify the boundary

- [ ] Product bug in dsh-passwords.
- [ ] DSH core bug or unsupported upstream behavior.
- [ ] Third-party plugin incompatibility.
- [ ] Deployment, reverse-proxy, TLS, DNS, or certificate issue.
- [ ] Documentation or usability gap.
- [ ] Security vulnerability requiring private handling.
- [ ] Duplicate, already fixed, unsupported version, or not actionable.

### 2. Reproduce safely

- [ ] Reproduce with test credentials and non-production data.
- [ ] Record the exact revision, package source, and deployment topology.
- [ ] Compare owner and subuser behavior where the report concerns authorization.
- [ ] Test both the normal path and the relevant failure path: 401/403/404/413, malformed upstream data, reconnect, timeout, archive/delete, and rollback as applicable.
- [ ] For HTTP or WebSocket proxy issues, inspect actual status, headers, upgrade path, framing, cookies, and upstream response instead of relying only on a browser message.

### 3. Protect contracts

- [ ] Do not weaken authentication or tenant isolation merely to make a plugin load.
- [ ] Do not broaden a WebSocket allowlist without identifying the endpoint owner and account scope.
- [ ] Do not treat a workspace grant as an automatic grant for every session.
- [ ] Recheck authorization after path resolution and after asynchronous state changes.
- [ ] Preserve upstream protocol fields, correlation IDs, pagination cursors, sequence numbers, and error semantics unless the gateway owns the transformation.
- [ ] Keep patch, update, install, uninstall, rollback, and unrelated plugin state isolated.
- [ ] Never include secrets or raw production logs in an issue, PR, test fixture, release note, or screenshot.

### 4. Close the loop

- [ ] Add or update a focused regression test for a confirmed product bug.
- [ ] Explain why a test is impractical when no test is added.
- [ ] Update compatibility documentation when a supported DSH boundary changes.
- [ ] Link the fixing commit, PR, or release from the issue.
- [ ] Do not close a compatibility or deployment issue solely because the local unit suite passes.
- [ ] Ask the reporter to retest only when the released or deployed artifact actually contains the fix.
- [ ] Record unresolved external dependencies and the next fact needed to decide them.

## Pull request checklist / PR 清单

- [ ] One focused change or one tightly coupled behavior.
- [ ] Issue linked with `Fixes #N`, `Closes #N`, or `Refs #N` where applicable.
- [ ] Root cause, affected roles, supported versions, compatibility impact, and rollback behavior described.
- [ ] `npm ci`, `npm run build`, and `npm test` run, with exact results and skips recorded.
- [ ] Security, authorization, tenant isolation, data-loss, race, reconnect, and failure behavior reviewed for affected paths.
- [ ] No accidental version bump, release asset, package publication, dependency churn, or generated-file noise.
- [ ] User-facing behavior and configuration changes documented in both README languages when appropriate.
- [ ] Contribution is compatible with `GPL-3.0-only`.

## Release checklist / 发布清单

- [ ] Release is cut from a reviewed, green, tagged source revision.
- [ ] GitHub source, npm package, Docker image, installers, and release assets identify the same version and source revision.
- [ ] DSH compatibility claims distinguish source-runtime support from npm/Docker availability.
- [ ] Bundled DSH version and package contents are inspected before publication.
- [ ] Release notes include user-visible changes, migration/configuration impact, known limits, and validation results in Chinese and English when the release is bilingual.
- [ ] No credentials, setup keys, private deployment URLs, or production data are present in release assets or notes.
- [ ] Post-release CI, package metadata, image metadata, and download links are checked.

## Lessons from repository history / 历史经验

1. **Version and topology are part of the bug report.** The repository has seen materially different behavior across DSH alpha/rc versions, npm-prefix layouts, bundled Docker, and reverse proxies.
2. **Browser symptoms are not ownership proof.** “Failed to load plugin”, 403, 404, 413, 502, and “history failed” can originate in DSH, a plugin, a proxy framing error, or dsh-passwords. Triage must identify the actual request and boundary.
3. **Multi-user reports need two identities and two resources.** Workspace visibility, session grants, archive state, file paths, and live event streams have repeatedly interacted; a single admin-only reproduction is insufficient.
4. **A successful fix needs artifact evidence.** Local source, npm package, Docker image, deployed server, and GitHub release can drift. Community replies should name the artifact and version that contains the fix.
5. **Fork contributions need explicit context.** Forks have produced useful fixes, but a PR body must still state license compatibility, tests, upstream assumptions, and whether the change is suitable for the main project rather than only a downstream deployment.
6. **Security boundaries are not convenience settings.** Passwords, cookies, setup keys, SSH data, paths, WebSocket upgrades, uploads, downloads, and session history require redaction and authorization evidence before public discussion.

## Repository maintenance follow-up / 仓库维护跟进

- [ ] Keep the templates aligned with supported DSH versions and installation methods.
- [ ] Add labels such as `bug`, `enhancement`, `compatibility`, `deployment`, `security`, `upstream`, `third-party`, `needs-triage`, and `needs-reproduction` if they are not already present.
- [ ] Use Discussions for broad ideas and deployment experience instead of allowing feature Issues to become unbounded design threads.
- [ ] Periodically review stale Issues and Discussions without closing active investigations merely because the current release changed.
- [ ] Review forks and downstream claims before linking them from project documentation.
- [ ] Keep a public changelog entry for fixes that change authorization, protocol compatibility, installation, or data migration behavior.
