# 测试样本来源

解析器的测试**全部**以本目录的文件为真值输入。文件名即来源，不要凭记忆编造新样本。

## 真实样本（`REAL`）

全部于 2026-10-03 在 Windows 11 26200（中文版）上真实抓取。
**命令的真实输出结构、字段顺序、中英文措辞、列宽一字未改**——这些才是解析器真正依赖的东西。

> **已脱敏**：发布到公开仓库前，所有标识性信息被替换为 RFC 定义的标准保留值 ——
> 主机名 → `DESKTOP-EXAMPLE`；MAC → `02:00:00:00:00:XX`；
> 内网/VPN IPv4 → `192.0.2.x` / `198.51.100.x`（RFC 5737 TEST-NET）；
> 全局与隧道 IPv6 → `2001:db8::/32`（RFC 3849）；适配器 GUID 与硬件型号 → 示例值；
> VPN 产品名 → `Example VPN`。
> 下面「关键特征」列里描述的都是**格式特征**（如「状态列是小写 `connected`」），
> 与具体某台机器无关，换成任何一台机器都成立。
>
> 例外：`114.114.114.114`、`223.5.5.5` 等**公共 DNS 服务地址**属于产品自身的数据，未脱敏。

抓取时机器状态（已脱敏）：以太网 192.0.2.10 / 网关 192.0.2.1，另有 Example VPN 虚拟网卡
（198.51.100.10 / 网关 198.51.100.1），WLAN 未连接。

| 文件 | 命令 | 这台机器上的关键特征 |
| :--- | :--- | :--- |
| `ipconfig_plain.txt` | `ipconfig` | **Example VPN 的网关排在以太网之前**；以太网段只有 IPv6 DNS 行，没有 IPv4 DNS 行 |
| `ipconfig_all.txt` | `ipconfig /all` | 以太网段含 `DNS 服务器 . : fe80::1%1`（只有 IPv6） |
| `ipconfig_all_gbk_raw.bin` | `ipconfig /all` | 同上的**原始 GBK 字节**，用于测 `decode_out` 的编码兼容 |
| `netsh_interfaces.txt` | `netsh interface ipv4 show interfaces` | 状态列是**英文小写** `connected` / `disconnected`；含环回（MTU 4294967295）与 vEthernet |
| `netsh_dnsservers.txt` | `netsh interface ipv4 show dnsservers` | 以太网为静态 DNS `114.114.114.114` + `192.0.2.1` |
| `route_print_default.txt` | `route print -4 0.0.0.0` | **活动路由**段 2 条 0.0.0.0/0（metric 9257 与 26），**永久路由**段另有 2 条但只有 4 列 |
| `ping_ok.txt` | `ping -n 4 -w 1000 www.baidu.com` | rc=0，4/4 回复 |
| `ping_loss100.txt` | `ping -n 4 -w 1000 198.51.100.1` | rc=1，4 次「请求超时」 |
| `ping_df_fail.txt` | `ping -f -l 1472 -n 1 -w 1500 223.5.5.5` | rc=1，报「需要拆分数据包但是设置 DF」 |
| `ping_df_ok.txt` | `ping -f -l 1464 -n 1 -w 1500 223.5.5.5` | rc=0，1/1 回复 |
| `ping_unknown_host.txt` | `ping -n 2 no-such-host.invalid` | rc=1，「Ping 请求找不到主机」 |
| `wlan_interfaces.txt` | `netsh wlan show interfaces` | WLAN 已断开 |
| `wlan_networks.txt` | `netsh wlan show networks mode=bssid` | **rc=1**：需要位置权限；输出的是权限提示而非网络列表 |

## 这台机器上实测到的关键事实（写测试时可依赖）

- `ping` **退出码可靠**：成功 0，所有失败形态（超时 / DF 过大 / 找不到主机）都是 1。
  判断成功不应靠子串猜。
- 「需要拆分数据包但是设置 DF」是**明确的上界信号**（包太大），
  「请求超时」是**不确定信号**（可能丢包），两者必须区分 —— 这是 MTU 二分探测正确性的关键。
- `route print` 的「活动路由」段 5 列（含接口列），「永久路由」段 4 列（无接口列），
  两段混解析会出错。
- 这台线路的路径 MTU 实测为 **1492（PPPoE）**：payload 1464 全通，1465 起 0/8 通过。
- `netsh interface ipv4 show interfaces` 的 MTU 列里，环回是 4294967295。

## 合成样本（`SYNTHETIC_` 前缀）

本机产生不了的场景（例如**已连接的 WiFi**、英文 Windows 界面），用文件名带
`SYNTHETIC_` 前缀的样本补充。**这类样本的"期望值"是人工依据格式规范推定的，
不是实测真值**，写测试时必须在注释里标明，不要和真实样本混为一谈。
