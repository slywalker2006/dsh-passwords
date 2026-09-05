# Contributing to dsh-passwords

感谢你为 dsh-passwords 做贡献。This project is a security-sensitive gateway around DeepSeek Harness, so a small, reproducible change with explicit authorization and compatibility evidence is more useful than a large unverified patch.

## Before you start / 开始之前

- Read the relevant sections of `README.md`, `README_en.md`, and `docs/compatibility-matrix.md`.
- 阅读 `README.md`、`README_en.md` 和 `docs/compatibility-matrix.md` 中的相关章节。
- Search existing Issues, Discussions, PRs, and Releases before opening a new thread.
- 提交新主题前搜索已有 Issue、Discussion、PR 和 Release。
- For upstream DSH behavior, use the official [DeepSeek Harness repository](https://github.com/deepseek-ai/deepseek-harness). For another plugin's behavior, report it to that plugin unless dsh-passwords demonstrably changes the request or response.
- 上游 DSH 行为请到官方 [DeepSeek Harness 仓库](https://github.com/deepseek-ai/deepseek-harness) 反馈；其他插件自身的问题请反馈给对应插件，除非能证明 dsh-passwords 改变了请求或响应。
- Do not use real production credentials or data while investigating.
- 排查时不要使用真实生产凭证或数据。

## What belongs where / 应该提交到哪里

| Situation / 情况 | Use / 入口 |
|---|---|
| Reproducible defect / 可复现缺陷 | [Bug report](https://github.com/slywalker2006/dsh-passwords/issues/new?template=bug_report.md) |
| Focused product idea / 明确的产品建议 | [Feature request](https://github.com/slywalker2006/dsh-passwords/issues/new?template=feature_request.md) |
| Security vulnerability / 安全漏洞 | Private security advisory or private maintainer contact, not a public Issue / 私密安全公告或私下联系维护者，不要公开提交 |
| Question, deployment experience, or broad design discussion / 问题、部署经验或开放设计讨论 | GitHub Discussions |
| Code or documentation change / 代码或文档修改 | Pull request |
| DSH core or third-party plugin defect / DSH 核心或第三方插件缺陷 | Upstream/plugin repository first / 优先到上游或插件仓库 |

## Reporting useful issues / 如何提交有效 Issue

Include the smallest complete reproduction:

1. dsh-passwords version and DSH version, including whether DSH came from npm, bundled Docker, or a source checkout.
2. Node.js version, OS/architecture, install method, reverse proxy/TLS topology, browser, and relevant plugin versions.
3. Account role: owner, subuser, or both. For authorization bugs, state the intended permission and the observed permission.
4. Exact steps, expected result, actual result, HTTP status/error code, and a short sanitized log excerpt.
5. A link to the upstream DSH or plugin issue when the boundary is uncertain.

Do not paste `.env`, `setup-key.txt`, JWTs, cookies, API keys, SSH passwords, private hostnames, complete production logs, or screenshots containing them. Replace values with placeholders such as `<redacted>` and preserve only the structure needed to reproduce the problem.

针对多用户、工作区、会话、文件下载/上传、WebSocket、SSH、Git、沙盒、Agent preset 或配额问题，请尽量同时给出“主用户正常、子用户异常”的对照结果。网络抖动、刷新后恢复、归档/删除状态、连接重连和并发操作也应注明。

## Development setup / 开发环境

Supported development baseline:

- Node.js `22.19+` or `24+`
- DSH `0.1.2-rc.1` for the current public compatibility baseline
- npm and git

Clone and install:

```bash
git clone https://github.com/slywalker2006/dsh-passwords.git
cd dsh-passwords
npm ci
```

Create a local `.env` only when a runtime test needs it. Keep local credentials outside Git and verify `git status` before every commit.

## Change boundaries / 变更边界

Keep each PR focused on one problem or one tightly coupled behavior. Avoid unrelated formatting, generated-file churn, version bumps, release assets, or dependency upgrades.

When changing a security or multi-tenant path, preserve these contracts unless the PR explicitly changes and documents them:

- Every authenticated request and WebSocket upgrade is authorized for the current account.
- A subuser cannot learn or operate on an unassigned workspace, session, file, SSH host, or plugin endpoint.
- Owner-only operations remain owner-only; a workspace grant does not silently grant every session.
- Archive, delete, revoke, ban, reconnect, and fallback states fail closed without erasing trusted state.
- Paths are normalized and rechecked after filesystem resolution; sensitive locations remain blocked.
- Upstream protocol fields and correlation data are forwarded without lossy rewriting unless the change owns that contract.
- Patch, install, update, and uninstall operations preserve rollback and leave unrelated plugins untouched.

For a compatibility change, identify the DSH version and concrete wire or bundle shape. Add a regression fixture for each supported layout you touch rather than matching only a version string.

## Testing requirements / 测试要求

Run the same checks as CI:

```bash
npm ci
npm run build
npm test
```

Tests use Node's built-in test runner through `tsx`. Add a focused regression test before or with a bug fix. Include malformed input, unauthorized access, failure, and reconnect/race cases when the changed path handles them. For browser or deployment behavior, add a manual verification note with the tested topology; do not claim a real end-to-end result from a unit test.

The CI matrix currently tests Node 22 and Node 24 on Ubuntu. A local pass does not replace testing the relevant DSH runtime, reverse proxy, or third-party plugin when the change crosses that boundary.

## Pull requests / 提交 PR

- Use a concise title such as `fix: ...`, `feat: ...`, `docs: ...`, `test: ...`, or `chore: ...`.
- Link an Issue with `Fixes #N`, `Closes #N`, or `Refs #N` when applicable.
- Explain the root cause, affected roles and versions, implementation boundary, compatibility impact, and rollback behavior.
- Include exact validation commands and results, including skipped tests.
- Keep secrets and production data out of commits, test fixtures, logs, screenshots, and PR descriptions.
- Do not publish npm, Docker, or GitHub Release artifacts from a normal feature PR. Release work is maintainer-owned and must be coordinated separately.

Maintainers may request a smaller diff, a regression test, an upstream reproduction, or a security review before merging. A PR can be closed without merging when it duplicates an existing fix, targets an unsupported upstream version, lacks a reproducible contract, or changes a security boundary without sufficient evidence.

## Review and merge policy / 审查与合并

Review focuses on behavior and risk in this order:

1. Authentication, authorization, tenant isolation, secret handling, path safety, and protocol integrity.
2. Data loss, rollback, lifecycle, race, reconnect, and failure behavior.
3. Supported DSH compatibility, install/upgrade/uninstall behavior, and user-visible regressions.
4. Tests, documentation, scope, and maintainability.

CI must pass before merge. Maintainers may squash commits when the final history remains understandable. Merge decisions are based on evidence and project fit, not PR size or contributor identity.

## Releases and compatibility / 发布与兼容性

The public package, bundled Docker image, installers, source archive, and GitHub Release must be produced from the same tagged source revision. Do not change the version in a feature PR. Compatibility claims must name the exact DSH versions tested and distinguish source-runtime support from npm/Docker availability.

For DSH or plugin upgrades, record whether the change affects HTTP routes, WebSocket paths, SSE/remote-mux framing, combo URLs, module-loader dependencies, cookies, workspace/session projections, or settings patches. “Works locally” is not enough for a claim that crosses these boundaries.

## Code of conduct / 行为准则

Be precise, respectful, and open to correction. Discuss evidence and observable behavior; do not attack people. Do not post credentials, private user data, exploit details, harassment, or coordinated abuse. Maintainers may edit labels, request redaction, lock threads, or close content that is unsafe, duplicative, out of scope, or not actionable.

## License / 许可证

By contributing, you agree that your contribution is provided under the repository's `GPL-3.0-only` license. Keep third-party code and assets clearly attributed and compatible with that license.
