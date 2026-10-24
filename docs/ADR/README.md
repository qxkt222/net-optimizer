# 架构决策记录（ADR）

记录 net-optimizer v2 中影响跨模块、且事后修改代价高的技术决策。一条决策一个文件，
编号递增；一经 `Accepted` 正文不再改写，后续变更用新 ADR 覆盖旧决策。

## 索引

| 编号 | 标题 | 状态 | 日期 |
|---|---|---|---|
| [0001](0001-tech-stack.md) | 技术栈与分发形态 | Accepted | 2026-10-24 |
| [0002](0002-report-architecture.md) | Report 架构：命令层只产出 Report | Accepted | 2026-10-24 |

## 约定

- 文件名：`NNNN-kebab-case-title.md`，四位编号，标题用英文短横线连接。
- 状态：`Proposed` → `Accepted` → `Superseded by NNNN` / `Deprecated`。
- 被覆盖的 ADR 保留原文，只改状态行并指向新 ADR。
- 每条 ADR 至少包含：背景、决策、被否方案与理由、后果、关联文档。
