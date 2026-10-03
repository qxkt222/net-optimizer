"""纯文本解析层 —— ``str -> models``，全项目文本解析的唯一真值点。

分层约束（见 BRIEF §5）：

- 只接收字符串、返回 ``netopt.models`` 里的 dataclass；
- 不 import subprocess、不做 IO、不 print、不读环境变量；
- 对畸形 / 权限报错 / 本地化差异等输入**不抛异常**：认不出来就返回空结果，
  绝不臆造数据。

本地化说明：中文 Windows 上关键字中英混杂（例如 ``netsh interface ipv4 show
interfaces`` 的列头是中文、状态列却是英文小写 ``connected``），因此关键字一律
按「中文 + 英文」双份匹配；状态判断用**整词比较**，绝不子串包含
（``disconnected`` 含 ``connected``，见 D2）。
"""

from __future__ import annotations

import re

from .models import ChannelOccupancy, DnsConfig, Gateway, Interface, PingStat, WlanInfo

__all__ = [
    "parse_ipconfig_addresses",
    "parse_ipconfig_dns",
    "parse_netsh_dnsservers",
    "parse_netsh_interfaces",
    "parse_ping",
    "parse_route_default",
    "parse_wlan_interfaces",
    "parse_wlan_networks",
    "ping_reply_ok",
]

# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_IPV6_RE = re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}(?:%[0-9A-Za-z]+)?")

#: ipconfig 的键行版式：``键 . . . . . . : 值``（点线是固定格式，值里可能有 IPv6 冒号）
_IPCONFIG_KV_RE = re.compile(r"^\s*(?P<key>.+?)\s*(?:\.\s*)+[:：]\s?(?P<val>.*)$")

#: 普通键行版式：``键 : 值``（netsh wlan / netsh dns 输出）
_PLAIN_KV_RE = re.compile(r"^\s*(?P<key>[^:：]+?)\s*[:：]\s*(?P<val>.*)$")


def _looks_like_ip(token: str) -> bool:
    """判断一个 token 是否是 IPv4/IPv6 地址字面量（含 ``%zone``）。"""
    return bool(_IPV4_RE.fullmatch(token) or _IPV6_RE.fullmatch(token))


def _first_ipv4(text: str) -> str | None:
    m = _IPV4_RE.search(text)
    return m.group(0) if m else None


def _norm_key(raw: str) -> str:
    """规整键名：去空白、去尾部点线填充、转小写。"""
    return raw.strip().rstrip(" .").strip().lower()


def _to_float(text: str) -> float | None:
    m = re.search(r"\d+(?:\.\d+)?", text)
    return float(m.group(0)) if m else None


# ---------------------------------------------------------------------------
# netsh interface ipv4 show interfaces  ->  list[Interface]
# ---------------------------------------------------------------------------

_NETSH_IFACE_ROW_RE = re.compile(
    r"^\s*(?P<index>\d+)\s+(?P<metric>\d+)\s+(?P<mtu>\d+)\s+(?P<state>\S+)\s+(?P<name>\S.*?)\s*$"
)
_NETSH_CONNECTED_VALUES = {"connected", "已连接"}

_LOOPBACK_MARKERS = ("loopback", "环回")
_VIRTUAL_MARKERS = ("vethernet", "hyper-v", "default switch", "wsl", "virtualbox", "vmware")
_VPN_MARKERS = ("vpn", "tap-", "tunnel", "隧道")
_WLAN_MARKERS = ("wlan", "wi-fi", "wifi", "无线")


def _state_is_connected(state: str) -> bool:
    """状态列整词比较。

    坑（D2）：不能写 ``"connected" in state`` —— ``disconnected`` 含该子串；
    也不能用大写 ``Connected`` 判断 —— 中文 Windows 输出的是小写。
    """
    return state.strip().lower() in _NETSH_CONNECTED_VALUES


def _classify_interface(name: str) -> tuple[str, bool]:
    """按名称给接口分类，返回 ``(kind, is_primary)``。

    loopback / virtual 不参与 DNS 配置（``is_primary=False``）：本机环回 MTU 是
    4294967295，虚拟交换机改 DNS 也没有意义。
    """
    low = name.lower()
    if any(k in low for k in _LOOPBACK_MARKERS):
        return "loopback", False
    if any(k in low for k in _VIRTUAL_MARKERS):
        return "virtual", False
    if any(k in low for k in _VPN_MARKERS):
        return "vpn", True
    if any(k in low for k in _WLAN_MARKERS):
        return "wlan", True
    return "ethernet", True


def parse_netsh_interfaces(text: str) -> list[Interface]:
    """解析 ``netsh interface ipv4 show interfaces``。

    行格式（列头可能是中文，状态列永远是英文小写）::

        Idx     Met         MTU          状态                名称
        ---  ----------  ----------  ------------  ---------------------------
          2          25        1500  connected     以太网
    """
    out: list[Interface] = []
    for line in text.splitlines():
        m = _NETSH_IFACE_ROW_RE.match(line)
        if m is None:
            continue
        name = m.group("name").strip()
        kind, primary = _classify_interface(name)
        out.append(
            Interface(
                name=name,
                index=int(m.group("index")),
                mtu=int(m.group("mtu")),
                connected=_state_is_connected(m.group("state")),
                kind=kind,
                is_primary=primary,
            )
        )
    return out


# ---------------------------------------------------------------------------
# route print -4 0.0.0.0  ->  Gateway | None
# ---------------------------------------------------------------------------

_ROUTE_ACTIVE_HDR_RE = re.compile(r"活动路由|Active Routes", re.IGNORECASE)
_ROUTE_PERSISTENT_HDR_RE = re.compile(r"永久路由|Persistent Routes", re.IGNORECASE)

#: 活动路由段每行 **5 列**：目标 / 掩码 / 网关 / 接口 / 跃点数。
#: 永久路由段只有 **4 列**（无接口列），本正则天然不会匹配到它。
_ROUTE_ROW_RE = re.compile(
    r"^\s*(?P<dest>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<mask>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<gw>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<iface>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<metric>\d+)\s*$"
)


def parse_route_default(text: str) -> Gateway | None:
    """从 ``route print -4 0.0.0.0`` 解析**活动路由**里 metric 最小的默认网关。

    这是 D1 的修复点：旧实现从 ``ipconfig`` 取**第一个**网关，在本机选中了
    Example VPN 的 198.51.100.1（ping 不通），真实的 192.0.2.1 被忽略。

    坑：``route print`` 有「活动路由」（5 列）和「永久路由」（4 列）两段，
    永久路由段既没有接口列、metric 也不是真实优先级，混解析会拿到错误数据。
    这里只在「活动路由」段内匹配 5 列行，遇到「永久路由」段头即停止。
    """
    in_active = False
    best: Gateway | None = None
    for line in text.splitlines():
        if _ROUTE_ACTIVE_HDR_RE.search(line):
            in_active = True
            continue
        if _ROUTE_PERSISTENT_HDR_RE.search(line):
            in_active = False
            continue
        if not in_active:
            continue
        m = _ROUTE_ROW_RE.match(line)
        if m is None:
            continue
        if m.group("dest") != "0.0.0.0" or m.group("mask") != "0.0.0.0":
            continue
        metric = int(m.group("metric"))
        if best is None or metric < best.metric:
            best = Gateway(ip=m.group("gw"), interface_ip=m.group("iface"), metric=metric)
    return best


# ---------------------------------------------------------------------------
# ipconfig / ipconfig /all  ->  适配器切块（内部工具）
# ---------------------------------------------------------------------------

_ADAPTER_HDR_RE = re.compile(
    r"^\s*(?P<kind>[^\s:]*适配器|[A-Za-z][A-Za-z0-9 ()./_-]*?[Aa]dapter)\s+(?P<name>.+?)\s*[:：]\s*$",
    re.IGNORECASE,
)

_DNS_KEYS = {"dns 服务器", "dns servers"}
_DHCP_ENABLED_KEYS = {"dhcp 已启用", "dhcp enabled"}
_IPV4_ADDR_KEYS = {"ipv4 地址", "ipv4 address", "ip address"}


def _iter_ipconfig_blocks(text: str) -> list[tuple[str, list[tuple[str, list[str]]]]]:
    """把 ipconfig 文本切成 ``[(适配器名, [(键, [值, 续行值...])]), ...]``。

    值可以跨行：ipconfig 会把多个网关 / 多个 DNS 以**更深缩进的裸地址续行**列出，
    续行本身没有键，靠 ``_looks_like_ip`` 识别并并入上一条键的值列表。
    """
    blocks: list[tuple[str, list[tuple[str, list[str]]]]] = []
    cur_name: str | None = None
    cur_items: list[tuple[str, list[str]]] = []
    for raw in text.splitlines():
        hdr = _ADAPTER_HDR_RE.match(raw)
        if hdr:
            if cur_name is not None:
                blocks.append((cur_name, cur_items))
            cur_name = hdr.group("name").strip()
            cur_items = []
            continue
        if cur_name is None:
            continue
        kv = _IPCONFIG_KV_RE.match(raw)
        if kv:
            key = _norm_key(kv.group("key"))
            val = kv.group("val").strip()
            cur_items.append((key, [val] if val else []))
            continue
        token = raw.strip()
        if token and cur_items and _looks_like_ip(token):
            cur_items[-1][1].append(token)
    if cur_name is not None:
        blocks.append((cur_name, cur_items))
    return blocks


def parse_ipconfig_dns(text: str) -> list[DnsConfig]:
    """解析 ``ipconfig /all`` 的 DNS 服务器，**IPv4 与 IPv6 都收**（D3）。

    旧实现只抓 IPv4 行，而本机以太网在 ``ipconfig`` 里 DNS 是 IPv6
    （``fe80::1%1``），于是返回空表、status 里 DNS 行静默消失。

    ``source`` 在 ipconfig 里没有直接字段，用同一适配器的
    ``DHCP 已启用`` 做保守推断：只有明确「否」才标 ``static``；
    有服务器但 DHCP 开着（或未知）标 ``dhcp``；没有服务器标 ``none``。
    只输出出现过 DNS 键行的适配器；重复地址按首次出现去重。
    """
    out: list[DnsConfig] = []
    for name, items in _iter_ipconfig_blocks(text):
        saw_dns = False
        dhcp_enabled: bool | None = None
        servers: list[str] = []
        for key, values in items:
            if key in _DHCP_ENABLED_KEYS:
                val = " ".join(values).strip().lower()
                dhcp_enabled = val.startswith(("是", "yes", "true"))
            elif key in _DNS_KEYS:
                saw_dns = True
                for val in values:
                    token = val.strip()
                    if _looks_like_ip(token) and token not in servers:
                        servers.append(token)
        if not saw_dns:
            continue
        if not servers:
            source = "none"
        elif dhcp_enabled is False:
            source = "static"
        else:
            source = "dhcp"
        out.append(DnsConfig(interface=name, servers=servers, source=source))
    return out


def parse_ipconfig_addresses(text: str) -> dict[str, str]:
    """解析 ``ipconfig`` 里每个适配器的 IPv4 地址（适配器名 -> IPv4）。"""
    out: dict[str, str] = {}
    for name, items in _iter_ipconfig_blocks(text):
        for key, values in items:
            if key not in _IPV4_ADDR_KEYS:
                continue
            found = None
            for val in values:
                found = _first_ipv4(val)
                if found:
                    break
            if found:
                out[name] = found
                break
    return out


# ---------------------------------------------------------------------------
# netsh interface ipv4 show dnsservers  ->  list[DnsConfig]
# ---------------------------------------------------------------------------

_NS_IFACE_RE = re.compile(
    r'^\s*(?:接口\s*"(?P<cn>.+?)"\s*的配置|Configuration for interface\s*"(?P<en>.+?)")',
    re.IGNORECASE,
)
_NS_STATIC_RE = re.compile(
    r"静态配置的\s*DNS\s*服务器|Statically Configured DNS Servers", re.IGNORECASE
)
_NS_DHCP_RE = re.compile(
    r"通过\s*DHCP\s*配置的\s*DNS\s*服务器|DNS servers configured through DHCP",
    re.IGNORECASE,
)


def _value_after(line: str, m: re.Match[str]) -> str:
    rest = line[m.end() :]
    if rest[:1] in (":", "："):
        rest = rest[1:]
    return rest.strip()


def parse_netsh_dnsservers(text: str) -> list[DnsConfig]:
    """解析 ``netsh interface ipv4 show dnsservers``，每个接口一条。

    ``source``：``static``（静态配置行）/ ``dhcp``（DHCP 行）/ ``none``
    （对应行为“无/None”或没有任何服务器，如本机的 Example VPN、WLAN 等）。
    服务器值可能是裸地址续行（``114.114.114.114`` 下一行再跟一个地址）。
    """
    out: list[DnsConfig] = []
    cur: dict[str, object] | None = None
    for line in text.splitlines():
        hdr = _NS_IFACE_RE.match(line)
        if hdr:
            name = (hdr.group("cn") or hdr.group("en") or "").strip()
            cur = {"name": name, "servers": [], "source": None}
            out.append(cur)  # type: ignore[arg-type]
            continue
        if cur is None:
            continue
        static_m = _NS_STATIC_RE.search(line)
        dhcp_m = _NS_DHCP_RE.search(line)
        if static_m or dhcp_m:
            cur["source"] = "static" if static_m else "dhcp"
            val = _value_after(line, static_m or dhcp_m)  # type: ignore[arg-type]
            servers = cur["servers"]
            assert isinstance(servers, list)
            for token in re.split(r"[\s,，]+", val):
                if token and _looks_like_ip(token) and token not in servers:
                    servers.append(token)
            continue
        token = line.strip()
        if token and _looks_like_ip(token):
            servers = cur["servers"]
            assert isinstance(servers, list)
            if cur["source"] in ("static", "dhcp") and token not in servers:
                servers.append(token)
    result: list[DnsConfig] = []
    for entry in out:
        servers = entry["servers"]
        assert isinstance(servers, list)
        source = entry["source"]
        if source is None and not servers:
            # 该块没有 DNS 配置行（非 netsh 正常输出）——不臆造
            continue
        if not servers:
            source = "none"
        result.append(
            DnsConfig(
                interface=str(entry["name"]),
                servers=list(servers),
                source=str(source),
            )
        )
    return result


# ---------------------------------------------------------------------------
# ping 输出  ->  PingStat / 三态判定
# ---------------------------------------------------------------------------

#: 往返时间：``时间=26ms`` / ``时间<1ms`` / ``time=26ms`` / ``time<1ms``
#: （``<1ms`` 记为 1.0，即真实值的上界；中文 “最短/平均” 统计行不含 时间=数字 形式）
_RTT_RE = re.compile(r"(?:时间|time)\s*[=<]\s*(?P<ms>\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)

#: DF 过大报文（明确上界信号）——中文与英文
_DF_PHRASES_RE = re.compile(
    r"fragmented\s+but\s+df|packet\s+needs\s+to\s+be\s+fragmented", re.IGNORECASE
)
_DF_ZH_MARKER = "需要拆分数据包"
#: ``DF`` 是 ICMP 标志的英文缩写，真实报文里是大写；按整词匹配避免误伤 "df.example.com"
_DF_TOKEN_RE = re.compile(r"\bDF\b")


def _df_failure(text: str) -> bool:
    return bool(_DF_ZH_MARKER in text or _DF_PHRASES_RE.search(text) or _DF_TOKEN_RE.search(text))


def parse_ping(text: str, target: str, count: int, code: int = 0) -> PingStat:
    """解析一次 ping 的输出。

    ``count`` 是**发起**的包数（调用方传入），丢失率按 ``count - 收到的回复数``
    计算。报文里没有任何往返时间时判失败：``avg_ms=None``、``loss_pct=100.0``。

    退出码在本机只能区分「成功(0) / 一切失败(1)」（超时、DF 过大、找不到主机
    全是 1），所以成功证据以报文中的**往返时间**为准，``code`` 仅作旁证。
    """
    times = [float(m.group("ms")) for m in _RTT_RE.finditer(text)]
    replies = len(times)
    if replies == 0:
        # 没有任何回复：无论退出码如何都判失败
        return PingStat(target=target, loss_pct=100.0, replies=0, raw=text)
    avg = sum(times) / replies
    jitter = sum(abs(t - avg) for t in times) / replies
    denom = count if count > 0 else replies
    loss = max(0.0, min(100.0, (denom - replies) / denom * 100.0)) if denom else 0.0
    return PingStat(
        target=target,
        min_ms=min(times),
        avg_ms=avg,
        max_ms=max(times),
        jitter_ms=jitter,
        loss_pct=loss,
        replies=replies,
        raw=text,
    )


def ping_reply_ok(text: str, code: int) -> bool | None:
    """ping 单包结果**三态**判定（D15 的核心）。

    - ``True``  —— 确定收到回复：退出码 0 **且**报文里有往返时间；
    - ``False`` —— 确定**包太大**：报文含 ``需要拆分数据包`` / ``DF`` /
      ``fragmented but DF`` / ``packet needs to be fragmented``；
    - ``None``  —— 不确定：超时、找不到主机、其他一切情况。

    本机经实测：``ping_df_fail`` 与 ``ping_loss100`` 的退出码**都是 1**，
    只靠退出码分不出「确定上界」和「不确定」，这就是 MTU 二分探测不稳定的根因。
    """
    if code == 0 and _RTT_RE.search(text):
        return True
    if _df_failure(text):
        return False
    return None


# ---------------------------------------------------------------------------
# netsh wlan show interfaces  ->  WlanInfo
# ---------------------------------------------------------------------------

_WLAN_IFACE_KEYS = {"名称", "name"}
_WLAN_STATE_KEYS = {"状态", "state"}
_WLAN_SIGNAL_KEYS = {"信号", "signal"}
_WLAN_CHANNEL_KEYS = {"信道", "channel"}
_WLAN_BAND_KEYS = {"频段", "band"}
_WLAN_RX_KEYS = {"接收速率", "receive rate"}
_WLAN_TX_KEYS = {"传输速率", "transmit rate"}
_WLAN_CONNECTED_STATES = {"connected", "已连接"}

#: 真实输出里速率键带单位后缀：``接收速率(Mbps)`` / ``Receive rate (Mbps)``
_WLAN_UNIT_SUFFIX_RE = re.compile(r"\s*[（(]\s*mbps\s*[)）]\s*$", re.IGNORECASE)


def parse_wlan_interfaces(text: str) -> WlanInfo:
    """解析 ``netsh wlan show interfaces``（中英文键都认）。

    坑：``BSSID`` 行是 AP 的 MAC，键必须与 ``SSID`` **精确相等**，
    不能用“包含 SSID”判断（否则会把 MAC 当网络名）。
    """
    info: dict[str, object] = {}
    for raw in text.splitlines():
        kv = _PLAIN_KV_RE.match(raw)
        if kv is None:
            continue
        key = _WLAN_UNIT_SUFFIX_RE.sub("", _norm_key(kv.group("key"))).strip()
        val = kv.group("val").strip()
        if key in _WLAN_IFACE_KEYS:
            info["interface"] = val or None
        elif key in _WLAN_STATE_KEYS:
            info["state"] = val or None
        elif key == "ssid":  # 精确匹配：BSSID 不算
            info["ssid"] = val or None
        elif key in _WLAN_SIGNAL_KEYS:
            pct = re.search(r"(\d+)", val)
            info["signal_pct"] = int(pct.group(1)) if pct else None
        elif key in _WLAN_CHANNEL_KEYS:
            ch = re.search(r"(\d+)", val)
            info["channel"] = int(ch.group(1)) if ch else None
        elif key in _WLAN_BAND_KEYS:
            info["band"] = val or None
        elif key in _WLAN_RX_KEYS:
            info["rx_mbps"] = _to_float(val)
        elif key in _WLAN_TX_KEYS:
            info["tx_mbps"] = _to_float(val)
    state = info.get("state")
    connected = bool(state) and str(state).strip().lower() in _WLAN_CONNECTED_STATES
    return WlanInfo(
        connected=connected,
        ssid=info.get("ssid"),  # type: ignore[arg-type]
        signal_pct=info.get("signal_pct"),  # type: ignore[arg-type]
        channel=info.get("channel"),  # type: ignore[arg-type]
        band=info.get("band"),  # type: ignore[arg-type]
        rx_mbps=info.get("rx_mbps"),  # type: ignore[arg-type]
        tx_mbps=info.get("tx_mbps"),  # type: ignore[arg-type]
        state=info.get("state"),  # type: ignore[arg-type]
        interface=info.get("interface"),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# netsh wlan show networks mode=bssid  ->  ChannelOccupancy
# ---------------------------------------------------------------------------

_WLAN_SSID_RE = re.compile(r"^\s*SSID\s+\d+\s*[:：]\s*(?P<ssid>.*?)\s*$", re.IGNORECASE)
_WLAN_BSSID_RE = re.compile(r"^\s*BSSID\s+\d*\s*[:：]\s*(?P<bssid>\S*)\s*$", re.IGNORECASE)
_WLAN_CH_RE = re.compile(r"^\s*(?:信道|Channel)\s*[:：]\s*(?P<ch>\d+)", re.IGNORECASE)
_WLAN_BAND_RE = re.compile(r"^\s*(?:频段|Band)\s*[:：]\s*(?P<band>.+?)\s*$", re.IGNORECASE)


def _band_of(band_text: str | None, channel: int | None) -> str | None:
    """先看显式频段字段，再按信道号推断（1-14 → 2.4GHz，>=32 → 5GHz）。"""
    if band_text:
        t = band_text.replace(" ", "").lower()
        if t.startswith("2.4"):
            return "2.4GHz"
        if t.startswith("5"):
            return "5GHz"
    if channel is None:
        return None
    if 1 <= channel <= 14:
        return "2.4GHz"
    if channel >= 32:
        return "5GHz"
    return None


def parse_wlan_networks(text: str) -> ChannelOccupancy:
    """解析 ``netsh wlan show networks mode=bssid``，统计信道占用。

    2.4GHz 与 5GHz 的**同号信道互不干扰**，必须按频段分开统计（``by_band``）。
    每个 BSSID 计 1 次；没有 BSSID 子块的网络按其网络级信道计 1 次。

    本机 ``netsh wlan show networks`` 因缺位置权限返回 rc=1 的提示文本（D16），
    此时输出里没有任何 ``SSID n :`` 行，函数自然返回**空的 ChannelOccupancy**，
    不崩、不造数据。
    """
    networks: list[dict[str, object]] = []
    cur_net: dict[str, object] | None = None
    cur_bss: dict[str, object] | None = None
    for line in text.splitlines():
        if _WLAN_SSID_RE.match(line):
            cur_net = {"channel": None, "band": None, "bssids": []}
            networks.append(cur_net)
            cur_bss = None
            continue
        if _WLAN_BSSID_RE.match(line):
            if cur_net is None:
                continue
            cur_bss = {"channel": None, "band": None}
            bssids = cur_net["bssids"]
            assert isinstance(bssids, list)
            bssids.append(cur_bss)
            continue
        m = _WLAN_CH_RE.match(line)
        if m:
            target = cur_bss if cur_bss is not None else cur_net
            if target is not None:
                target["channel"] = int(m.group("ch"))
            continue
        m = _WLAN_BAND_RE.match(line)
        if m:
            target = cur_bss if cur_bss is not None else cur_net
            if target is not None:
                target["band"] = m.group("band").strip()
    by_band: dict[str, dict[int, int]] = {}
    for net in networks:
        net_ch = net["channel"]
        net_band = net["band"]
        bssids = net["bssids"]
        assert isinstance(bssids, list)
        entries = bssids if bssids else [None]
        for entry in entries:
            # BSSID 子块没写信道/频段时回退到网络级的值
            channel = net_ch
            band_text = net_band
            if entry is not None:
                if entry["channel"] is not None:
                    channel = entry["channel"]
                if entry["band"] is not None:
                    band_text = entry["band"]
            band = _band_of(
                band_text if isinstance(band_text, str) else None,
                channel if isinstance(channel, int) else None,
            )
            if band is None or not isinstance(channel, int):
                continue
            per_band = by_band.setdefault(band, {})
            per_band[channel] = per_band.get(channel, 0) + 1
    return ChannelOccupancy(by_band=by_band)
