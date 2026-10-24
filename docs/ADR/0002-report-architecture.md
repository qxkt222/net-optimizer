# 0002 Report 架构：命令层只产出 Report

- 状态：Accepted
- 日期：2026-10-24
- 关联：`docs/SPEC.md` §4 / §5.1 / §9；`docs/TASKS.md` T1.1、T1.4–T1.8、T5.1

## 背景

v1 的命令函数把「探测 → 判断 → 着色 → print」写在同一条调用链里。GUI 复用 CLI 的方式是
替换 `sys.stdout`、捕获文本、再用正则剥离 ANSI 转义。这套做法在 v2 引入 rich / httpx 后
不可继续：

- 输出是字符串，JSON、GUI、测试都拿不到稳定结构，只能断言文案；
- 阈值与建议散落在渲染代码里，同一条延迟在不同命令下可能有不同结论；
- 全局替换 stdout 与工作线程组合时行为不可控，rich 的首次渲染还会惰性加载资源。

## 决策

1. **命令层只产出 `Report`。** `netopt/commands/*` 的 builder 负责探测、调用 analysis、
   组装 `Report`；不 `print`、不 `sys.exit`、不直接渲染。修复命令产出 `FixPlan` / `FixResult`，
   回滚命令产出 `UndoResult`，同样不打印。
2. **渲染集中在 `netopt/render/`。** `render/text.py` 用 rich 输出终端文本，并提供
   `render_plain` 返回无 ANSI 纯文本；`render/json.py` 直接调用
   `Report.model_dump_json()`，不裁剪、不改字段。
3. **CLI 与 GUI 消费同一份数据。** `cli.py` 负责选择 text / json 渲染并映射退出码；
   `gui.py` 在工作线程只构建 `Report`，回到主线程后调用 `render_plain` 插入文本框。
   JSON、终端、GUI 三条路径看到的字段完全一致。

依赖方向由 `tach.toml` 固化：`render` 只依赖 `domain`；`commands` 不依赖 `render`；
`cli` 依赖 `commands` + `render`。

## 被否方案

- **继续 print + stdout 重定向。** 需要维护 ANSI 正则与线程级 stdout 替换；rich 的
  `Live` / 表格在重定向下容易产生控制字符与乱序；测试只能比对文本，字段一变就大面积
  失败；GUI 与 CLI 的输出还可能因终端宽度不同而漂移。
- **每个前端各写一套渲染。** CLI、GUI、JSON 各维护一份取数、阈值与文案，改一处要改
  三处；字段名与语义容易分叉，`--json` 与界面显示对不上，也无法用同一份快照测试兜底。

## 后果

- **GUI 无线程 stdout 风险。** GUI 不再替换 `sys.stdout`，也不需要解析 ANSI；rich 的
  首次使用被固定在主线程（`gui.py` 的注释记录了该约束），避免 Windows 上的
  0x80000003 崩溃。
- **JSON / 终端 / GUI 一致。** 三者都从同一个 `Report` 派生；`schema_version` 是跨端契约，
  破坏性字段变更必须升版本。
- **命令层可测。** builder 可注入假 runner、`FakeSystemApi`、假时钟与假 builder，测试断言
  对象字段而不是终端文本；渲染层另有独立快照测试。
- **代价。** 命令层不能顺手打印进度或调试信息（只能走 stderr 或返回值）；新增展示内容
  必须先扩展 `Report` 契约，不能在前端临时拼字符串。
