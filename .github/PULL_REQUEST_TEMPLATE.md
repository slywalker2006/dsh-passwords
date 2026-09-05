## Summary / 摘要

<!-- What problem does this PR solve? Keep the scope narrow and link the issue. -->
<!-- 本 PR 解决什么问题？请保持范围聚焦并关联 Issue。 -->

Fixes #

## Change type / 变更类型

- [ ] Bug fix / 问题修复
- [ ] Feature / 新功能
- [ ] Compatibility / 上游兼容
- [ ] Security / 安全修复
- [ ] Documentation / 文档
- [ ] Tests or CI / 测试或 CI
- [ ] Refactor without behavior change / 不改变行为的重构

## Scope / 影响范围

- Affected components / 受影响组件:
- Affected account roles / 受影响账号角色: owner / subuser / both
- Affected DSH versions / 受影响 DSH 版本:
- Install/deployment impact / 安装或部署影响:
- Data, permission, or migration impact / 数据、权限或迁移影响:

<!-- For changes involving sessions, workspaces, files, WebSockets, SSH, Git, sandbox, quotas, or plugins, describe the trust boundary and authorization decision. -->
<!-- 涉及会话、工作区、文件、WebSocket、SSH、Git、沙盒、配额或插件时，请说明信任边界与授权判断。 -->

## Implementation notes / 实现说明

<!-- Explain important invariants, fallback behavior, lifecycle/rollback behavior, and any upstream assumptions. -->
<!-- 说明关键不变量、兜底行为、生命周期/回滚行为，以及对上游的假设。 -->

## Testing / 测试

- [ ] `npm ci`
- [ ] `npm run build`
- [ ] `npm test`
- [ ] Focused regression test added or updated / 已新增或更新针对性回归测试
- [ ] Manual browser or deployment test performed where relevant / 必要时已完成浏览器或部署人工测试

### Results / 结果

<!-- Include exact commands and concise results. Mention skipped tests and why. -->
<!-- 写出确切命令和简要结果；如有跳过测试，请说明原因。 -->

```text

```

## Security and privacy / 安全与隐私

- [ ] No secrets, tokens, API keys, cookies, `.env` values, private URLs, or production data are included.
- [ ] 未包含密钥、token、API key、Cookie、`.env` 值、私有 URL 或生产数据。
- [ ] Authorization and tenant isolation were reviewed for affected paths.
- [ ] 已审查受影响路径的授权和租户隔离。
- [ ] Error responses and logs do not disclose credentials or unauthorized resource identifiers.
- [ ] 错误响应和日志不会泄露凭证或未授权资源标识。

## Compatibility and release checks / 兼容性与发布检查

- [ ] The change preserves supported DSH compatibility or documents the intentional boundary.
- [ ] 已保持支持的 DSH 兼容性，或记录了有意调整的边界。
- [ ] Generated files and package contents were updated only when required.
- [ ] 仅在必要时更新生成文件和发布包内容。
- [ ] No package version, tag, registry, or Docker publication was changed unintentionally.
- [ ] 未意外修改包版本、tag、registry 或 Docker 发布内容。

## Checklist / 检查清单

- [ ] The branch is based on the current `main`.
- [ ] 分支基于当前 `main`。
- [ ] The diff is focused; unrelated formatting or generated churn is removed.
- [ ] diff 范围聚焦，已删除无关格式化和生成文件噪声。
- [ ] Documentation was updated for user-visible behavior or configuration changes.
- [ ] 用户可见行为或配置变化已同步文档。
- [ ] I agree to license my contribution under GPL-3.0-only.
- [ ] 我同意本贡献按 GPL-3.0-only 许可证授权。
