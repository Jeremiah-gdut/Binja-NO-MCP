# 问题跟踪：GitHub

本仓库的 Issue 和 PRD 均使用 GitHub Issues 管理，所有操作使用 `gh` CLI。

## 常用操作

- 创建：`gh issue create --title "..." --body "..."`
- 查看：`gh issue view <number> --comments`
- 列表：`gh issue list --state open`
- 评论：`gh issue comment <number> --body "..."`
- 添加／移除标签：`gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- 关闭：`gh issue close <number> --comment "..."`

在此仓库克隆目录中运行时，`gh` 会根据 `git remote -v` 自动识别仓库。

## PR 是否纳入分诊

**外部 PR 不纳入分诊队列。**

## 技能约定

当技能要求“发布到问题跟踪器”时，创建 GitHub Issue。
当技能要求“读取相关工单”时，运行 `gh issue view <number> --comments`。
