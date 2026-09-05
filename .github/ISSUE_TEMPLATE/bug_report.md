---
name: Bug report / 问题报告
about: Report a reproducible defect in dsh-passwords / 报告可复现的问题
title: "[Bug] "
labels: "bug, needs-triage"
assignees: ""
---

## Before opening / 提交前

- [ ] I searched existing issues, discussions, and releases.
- [ ] 我已搜索现有 Issue、Discussion 和 Releases。
- [ ] This is a dsh-passwords issue, not only an upstream DSH or third-party plugin issue.
- [ ] 我确认问题属于 dsh-passwords，而不只是上游 DSH 或第三方插件。
- [ ] I removed passwords, tokens, API keys, cookies, `.env` values, private URLs, and personal data.
- [ ] 我已删除密码、token、API key、Cookie、`.env` 值、私有 URL 和个人数据。

## Environment / 环境

- dsh-passwords version / 版本:
- DSH version and source (`npm`, bundled Docker, or source build) / DSH 版本及来源：
- Node.js version / Node.js 版本:
- OS and architecture / 操作系统与架构:
- Install method / 安装方式：`npm` / `git` / `install.sh` / `install.bat` / Docker / other
- Reverse proxy or TLS termination / 反向代理或 TLS 终结：none / nginx / Caddy / Cloudflare / other
- Browser and version, if UI-related / 浏览器及版本（如涉及 UI）：
- Related plugin names and versions, if relevant / 相关插件及版本（如适用）：

## What happened? / 发生了什么？

<!-- Describe the user-visible result and the expected result. Include the affected account role: owner, subuser, or both. -->
<!-- 描述实际结果和预期结果，并注明受影响的账号角色：主用户、子用户或两者。 -->

## Reproduction steps / 复现步骤

1.
2.
3.

## Evidence / 证据

<!-- Include a minimal, sanitized log excerpt, HTTP status/code, request path without credentials, or screenshot. Do not paste full production logs or secret-bearing headers. -->
<!-- 可附最小化且已脱敏的日志、HTTP 状态码/错误码、不含凭证的请求路径或截图。不要粘贴完整生产日志或含密钥的请求头。 -->

```text
Paste sanitized evidence here / 在此粘贴脱敏证据
```

## Scope and authorization / 作用域与授权

<!-- For multi-user, workspace, session, file, WebSocket, SSH, Git, sandbox, or quota issues, state the intended permission and the observed permission. -->
<!-- 对多用户、工作区、会话、文件、WebSocket、SSH、Git、沙盒或配额问题，请说明期望权限与实际权限。 -->

- Account role / 账号角色:
- Intended permission / 期望权限:
- Observed permission or status / 实际权限或状态:
- Resource identifiers, redacted if sensitive / 资源标识（敏感时脱敏）:

## Additional context / 补充信息

<!-- Add a link to the relevant upstream DSH issue or plugin repository when the behavior may be upstream-owned. -->
<!-- 如可能属于上游，请附相关 DSH Issue 或插件仓库链接。 -->

## Maintainer checklist / 维护者检查项

- [ ] Reproduced on a supported DSH version or identified as upstream-owned.
- [ ] Classified as bug, compatibility, security, deployment, or third-party plugin issue.
- [ ] Added a regression test or documented why a test is not practical.
- [ ] Checked authorization, data isolation, and failure behavior before changing a fail-closed path.
