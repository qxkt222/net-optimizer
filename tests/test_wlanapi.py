# -*- coding: utf-8 -*-
"""``netopt.system.wlanapi`` 的纯函数、结构遍历与真机只读测试。

这里**不修改系统、不联网**：

- 换算函数直接用合成数据；
- 变长列表遍历用 ``ctypes`` 合成缓冲区构造；
- 真机测试只调用 ``wifi_state()`` / ``wifi_scan()``，不写任何配置。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
import struct
from typing import Any

import pytest

from netopt.domain.models import WifiNetwork, WifiScan, WifiState
from netopt.system import wlanapi
from netopt.system.api import SystemUnavailable

# ---------------------------------------------------------------------------
# 频率 → 信道 / 频段
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("freq_mhz", "channel", "band"),
    [
        (2412, 1, "2.4GHz"),
        (2437, 6, "2.4GHz"),
        (2462, 11, "2.4GHz"),
        (2484, 15, "2.4GHz"),
        (5180, 36, "5GHz"),
        (5745, 149, "5GHz"),
        (5825, 165, "5GHz"),
        (5955, 1, "6GHz"),
        (6135, 37, "6GHz"),
        (7115, 233, "6GHz"),
    ],
)
def test_channel_and_band_known_frequencies(freq_mhz: int, channel: int, band: str) -> None:
    assert wlanapi._channel_and_band(freq_mhz) == (channel, band)


@pytest.mark.parametrize("freq_mhz", [0, 2400, 2411, 2485, 5000, 5179, 5826, 5954, 7116])
def test_channel_and_band_out_of_range(freq_mhz: int) -> None:
    assert wlanapi._channel_and_band(freq_mhz) == (None, None)


@pytest.mark.parametrize(
    ("channel", "band"),
    [(1, "2.4GHz"), (14, "2.4GHz"), (36, "5GHz"), (177, "5GHz"), (233, "6GHz"), (0, None)],
)
def test_band_from_channel_fallback(channel: int, band: str | None) -> None:
    assert wlanapi._band_from_channel(channel) == band


# ---------------------------------------------------------------------------
# SSID / BSSID / 信号 / 速率
# ---------------------------------------------------------------------------


def test_decode_ssid_ascii() -> None:
    assert wlanapi._decode_ssid(b"Home\x00\x00", 4) == "Home"


def test_decode_ssid_utf8() -> None:
    raw = "网络".encode()
    assert wlanapi._decode_ssid(raw, len(raw)) == "网络"


def test_decode_ssid_invalid_bytes_are_replaced() -> None:
    assert wlanapi._decode_ssid(b"\xff\xfe", 2) == "��"


def test_decode_ssid_truncated_multibyte_is_replaced() -> None:
    # 不完整的三字节 UTF-8 序列：只产生一个替换符，不抛异常
    assert wlanapi._decode_ssid(b"\xe7\xbd", 2) == "�"


def test_decode_ssid_empty_returns_none() -> None:
    assert wlanapi._decode_ssid(b"\x00" * 32, 0) is None


def test_decode_ssid_length_larger_than_buffer_is_capped() -> None:
    assert wlanapi._decode_ssid(b"AB", 10) == "AB"


def test_decode_ssid_length_larger_than_max_is_capped() -> None:
    raw = b"A" * 40
    assert wlanapi._decode_ssid(raw, 40) == "A" * 32


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (bytes(range(6)), "00:01:02:03:04:05"),
        (b"\xaa\xbb\xcc\xdd\xee\xff", "AA:BB:CC:DD:EE:FF"),
        (b"\x00\x00\x00\x00\x00\x00", "00:00:00:00:00:00"),
    ],
)
def test_format_bssid(raw: bytes, expected: str) -> None:
    assert wlanapi._format_bssid(raw) == expected


@pytest.mark.parametrize(
    ("quality", "expected"), [(0, 0), (42, 42), (100, 100), (101, 100), (255, 100), (-5, 0)]
)
def test_signal_pct_clamped(quality: int, expected: int) -> None:
    assert wlanapi._signal_pct(quality) == expected


def test_kbps_to_mbps() -> None:
    assert wlanapi._kbps_to_mbps(866700) == pytest.approx(866.7)
    assert wlanapi._kbps_to_mbps(144400) == pytest.approx(144.4)
    assert wlanapi._kbps_to_mbps(0) == pytest.approx(0.0)


def test_auth_and_cipher_names() -> None:
    assert wlanapi._auth_name(1) == "open"
    assert wlanapi._auth_name(7) == "WPA2-PSK"
    assert wlanapi._auth_name(9) == "WPA3-SAE"
    assert wlanapi._auth_name(0) is None
    assert wlanapi._cipher_name(0) == "none"
    assert wlanapi._cipher_name(4) == "CCMP"
    assert wlanapi._cipher_name(0xFFFF) is None


# ---------------------------------------------------------------------------
# 变长结构遍历：用合成字节缓冲区验证
# ---------------------------------------------------------------------------


def _build_bss_buffer(entries: list[tuple[bytes, bytes, int, int]]) -> tuple[Any, Any]:
    """按 ``WLAN_BSS_LIST`` 布局拼一块缓冲区，返回 (buffer, list_pointer)。

    每个 ``entries`` 元素是 ``(ssid, bssid, link_quality, center_freq_khz)``。
    """
    entry_size = ctypes.sizeof(wlanapi._WLAN_BSS_ENTRY)
    header_size = wlanapi._WLAN_BSS_LIST.wlanBssEntries.offset
    buffer = ctypes.create_string_buffer(header_size + entry_size * len(entries))
    list_ptr = ctypes.cast(buffer, ctypes.POINTER(wlanapi._WLAN_BSS_LIST))
    list_ptr.contents.dwTotalSize = len(buffer)
    list_ptr.contents.dwNumberOfItems = len(entries)
    base = ctypes.addressof(buffer) + header_size
    for index, (ssid, bssid, quality, freq_khz) in enumerate(entries):
        entry = wlanapi._WLAN_BSS_ENTRY.from_address(base + index * entry_size)
        entry.dot11Ssid.uSSIDLength = len(ssid)
        for offset, byte in enumerate(ssid):
            entry.dot11Ssid.ucSSID[offset] = byte
        for offset, byte in enumerate(bssid):
            entry.dot11Bssid[offset] = byte
        entry.uLinkQuality = quality
        entry.ulChCenterFrequency = freq_khz
    return buffer, list_ptr


def test_iter_bss_entries_walks_synthetic_buffer() -> None:
    buffer, list_ptr = _build_bss_buffer(
        [
            (b"Home", b"\xaa\xbb\xcc\xdd\xee\xff", 80, 2437000),
            (b"Office", b"\x11\x22\x33\x44\x55\x66", 45, 5180000),
        ]
    )
    assert buffer  # 保持缓冲区存活，直到遍历结束

    entries = list(wlanapi._iter_bss_entries(list_ptr))

    assert len(entries) == 2
    first, second = entries
    assert wlanapi._decode_ssid(bytes(first.dot11Ssid.ucSSID), first.dot11Ssid.uSSIDLength) == (
        "Home"
    )
    assert wlanapi._format_bssid(bytes(first.dot11Bssid)) == "AA:BB:CC:DD:EE:FF"
    assert wlanapi._channel_and_band(first.ulChCenterFrequency // 1000) == (6, "2.4GHz")
    assert wlanapi._decode_ssid(bytes(second.dot11Ssid.ucSSID), second.dot11Ssid.uSSIDLength) == (
        "Office"
    )
    assert first.uLinkQuality == 80
    assert second.ulChCenterFrequency == 5180000


def test_iter_bss_entries_empty_list() -> None:
    buffer, list_ptr = _build_bss_buffer([])
    assert buffer
    assert list(wlanapi._iter_bss_entries(list_ptr)) == []


def test_iter_bss_entries_null_pointer() -> None:
    assert list(wlanapi._iter_bss_entries(None)) == []


def test_bss_entry_to_network() -> None:
    buffer, list_ptr = _build_bss_buffer([(b"Cafe", b"\x02\x00\x00\x00\x00\x01", 72, 5745000)])
    assert buffer
    entry = next(wlanapi._iter_bss_entries(list_ptr))
    network = wlanapi._bss_to_network(entry, {b"Cafe": ("WPA2-PSK", "CCMP")})

    assert isinstance(network, WifiNetwork)
    assert network.ssid == "Cafe"
    assert network.bssid == "02:00:00:00:00:01"
    assert network.signal_pct == 72
    assert (network.channel, network.band) == (149, "5GHz")
    assert (network.auth, network.encryption) == ("WPA2-PSK", "CCMP")


def test_bss_entry_to_network_without_security() -> None:
    buffer, list_ptr = _build_bss_buffer([(b"Open", b"\x00\x00\x00\x00\x00\x02", 30, 2412000)])
    assert buffer
    entry = next(wlanapi._iter_bss_entries(list_ptr))
    network = wlanapi._bss_to_network(entry, {})

    assert (network.auth, network.encryption) == (None, None)
    assert network.channel == 1


def _fill_ssid(target: wlanapi._DOT11_SSID, raw: bytes) -> None:
    """把字节写进 ``DOT11_SSID``（测试里手工构造连接属性用）。"""
    target.uSSIDLength = len(raw)
    for offset, byte in enumerate(raw):
        target.ucSSID[offset] = byte


def test_connection_to_state_maps_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """连接属性到 WifiState 的字段映射（本机无网卡，DLL 查询用桩替代）。"""
    attrs = wlanapi._WLAN_CONNECTION_ATTRIBUTES()
    attrs.isState = wlanapi._STATE_CONNECTED
    assoc = attrs.wlanAssociationAttributes
    _fill_ssid(assoc.dot11Ssid, "家庭网络".encode())
    for offset, byte in enumerate(b"\xaa\xbb\xcc\xdd\xee\xff"):
        assoc.dot11Bssid[offset] = byte
    assoc.wlanSignalQuality = 88
    assoc.ulRxRate = 866700
    assoc.ulTxRate = 1201000

    monkeypatch.setattr(wlanapi, "_query_bss_frequency", lambda *args: 5180000)
    interface = wlanapi._Interface(
        guid=wlanapi._GUID(),
        description="WLAN",
        state=wlanapi._STATE_CONNECTED,
    )

    state = wlanapi._connection_to_state(None, interface, attrs)

    assert state.connected is True
    assert state.interface == "WLAN"
    assert state.ssid == "家庭网络"
    assert state.bssid == "AA:BB:CC:DD:EE:FF"
    assert state.signal_pct == 88
    assert (state.channel, state.band) == (36, "5GHz")
    assert state.rx_mbps == pytest.approx(866.7)
    assert state.tx_mbps == pytest.approx(1201.0)
    assert state.state == "connected"


# ---------------------------------------------------------------------------
# 注入测试：用假 DLL 覆盖成功 / 失败 / 释放路径
# ---------------------------------------------------------------------------


class _FakeDll:
    """``wlanapi.dll`` 的 Python 替身，记录调用并回写 ``byref`` 指针。

    本机没有无线网卡，真机只能走到「零接口」分支。这里通过
    monkeypatch ``wlanapi._dll`` 注入替身，把成功、失败和释放路径都跑到。
    返回值与指针写回方式模仿真实 API：``byref`` 参数用 ``ctypes.cast`` 回写。
    """

    def __init__(self) -> None:
        self.open_code = 0
        self.enum_code = 0
        self.enum_interfaces: list[tuple[bytes, str, int]] = []
        self.query_results: dict[int, tuple[int, bytes | None]] = {}
        self.scan_code = 0
        self.bss_code = 0
        self.bss_entries: list[tuple[bytes, bytes, int, int]] = []
        self.available_code = 0
        self.available_entries: list[tuple[bytes, int, int]] = []
        self.queries: list[int] = []
        self.scan_calls = 0
        self.closed = 0
        self.freed: list[int] = []
        self._alive: list[Any] = []

    def WlanOpenHandle(self, version: Any, reserved: Any, negotiated: Any, handle: Any) -> int:
        _write_dword(negotiated, 2)
        if self.open_code == 0:
            _write_pointer(handle, 0x1234)
        return self.open_code

    def WlanCloseHandle(self, handle: Any, reserved: Any) -> int:
        self.closed += 1
        return 0

    def WlanFreeMemory(self, ptr: Any) -> None:
        self.freed.append(_address_of(ptr))

    def WlanEnumInterfaces(self, handle: Any, reserved: Any, out: Any) -> int:
        if self.enum_code != 0:
            return self.enum_code
        if not self.enum_interfaces:
            _write_pointer(out, 0)
            return 0
        buffer = _build_interface_buffer(self.enum_interfaces)
        self._alive.append(buffer)
        _write_pointer(out, ctypes.addressof(buffer))
        return 0

    def WlanQueryInterface(
        self,
        handle: Any,
        guid: Any,
        opcode: int,
        reserved: Any,
        size_out: Any,
        data_out: Any,
        kind_out: Any,
    ) -> int:
        self.queries.append(opcode)
        code, payload = self.query_results.get(opcode, (0, None))
        if code != 0:
            return code
        if payload is None:
            _write_dword(size_out, 0)
            _write_pointer(data_out, 0)
            return 0
        buffer = ctypes.create_string_buffer(payload)
        self._alive.append(buffer)
        _write_dword(size_out, len(payload))
        _write_pointer(data_out, ctypes.addressof(buffer))
        return 0

    def WlanScan(self, handle: Any, guid: Any, ssid: Any, raw: Any, reserved: Any) -> int:
        self.scan_calls += 1
        return self.scan_code

    def WlanGetNetworkBssList(
        self,
        handle: Any,
        guid: Any,
        ssid: Any,
        bss_type: Any,
        security: Any,
        reserved: Any,
        out: Any,
    ) -> int:
        if self.bss_code != 0:
            return self.bss_code
        if not self.bss_entries:
            _write_pointer(out, 0)
            return 0
        buffer, _ = _build_bss_buffer(self.bss_entries)
        self._alive.append(buffer)
        _write_pointer(out, ctypes.addressof(buffer))
        return 0

    def WlanGetAvailableNetworkList(
        self, handle: Any, guid: Any, flags: Any, reserved: Any, out: Any
    ) -> int:
        if self.available_code != 0:
            return self.available_code
        if not self.available_entries:
            _write_pointer(out, 0)
            return 0
        buffer = _build_available_buffer(self.available_entries)
        self._alive.append(buffer)
        _write_pointer(out, ctypes.addressof(buffer))
        return 0


def _write_pointer(ref: Any, address: int) -> None:
    """把地址写进调用方用 ``byref`` 传入的 ``void **``。"""
    ctypes.cast(ref, ctypes.POINTER(ctypes.c_void_p)).contents.value = address


def _write_dword(ref: Any, value: int) -> None:
    """把整数写进调用方用 ``byref`` 传入的 ``DWORD *``。"""
    ctypes.cast(ref, ctypes.POINTER(wintypes.DWORD)).contents.value = value


def _address_of(ptr: Any) -> int:
    """取指针地址（``None`` / 空指针记 0），用于断言释放调用。"""
    if ptr is None:
        return 0
    if isinstance(ptr, ctypes.c_void_p):
        return int(ptr.value or 0)
    return int(ctypes.cast(ptr, ctypes.c_void_p).value or 0)


def _build_interface_buffer(entries: list[tuple[bytes, str, int]]) -> Any:
    """按 ``WLAN_INTERFACE_INFO_LIST`` 布局拼合成缓冲区。"""
    size = ctypes.sizeof(wlanapi._WLAN_INTERFACE_INFO)
    header = wlanapi._WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
    buffer = ctypes.create_string_buffer(header + size * len(entries))
    list_ptr = ctypes.cast(buffer, ctypes.POINTER(wlanapi._WLAN_INTERFACE_INFO_LIST))
    list_ptr.contents.dwNumberOfItems = len(entries)
    base = ctypes.addressof(buffer) + header
    for index, (guid, description, state) in enumerate(entries):
        info = wlanapi._WLAN_INTERFACE_INFO.from_address(base + index * size)
        ctypes.memmove(ctypes.byref(info.InterfaceGuid), guid[:16], 16)
        info.strInterfaceDescription = description
        info.isState = state
    return buffer


def _build_available_buffer(entries: list[tuple[bytes, int, int]]) -> Any:
    """按 ``WLAN_AVAILABLE_NETWORK_LIST`` 布局拼合成缓冲区。"""
    size = ctypes.sizeof(wlanapi._WLAN_AVAILABLE_NETWORK)
    header = wlanapi._WLAN_AVAILABLE_NETWORK_LIST.Network.offset
    buffer = ctypes.create_string_buffer(header + size * len(entries))
    list_ptr = ctypes.cast(buffer, ctypes.POINTER(wlanapi._WLAN_AVAILABLE_NETWORK_LIST))
    list_ptr.contents.dwNumberOfItems = len(entries)
    base = ctypes.addressof(buffer) + header
    for index, (ssid, auth, cipher) in enumerate(entries):
        entry = wlanapi._WLAN_AVAILABLE_NETWORK.from_address(base + index * size)
        entry.dot11Ssid.uSSIDLength = len(ssid)
        for offset, byte in enumerate(ssid):
            entry.dot11Ssid.ucSSID[offset] = byte
        entry.dot11DefaultAuthAlgorithm = auth
        entry.dot11DefaultCipherAlgorithm = cipher
    return buffer


def _connection_payload(
    state: int, ssid: bytes, bssid: bytes, quality: int, rx_kbps: int, tx_kbps: int
) -> bytes:
    """把一份 ``WLAN_CONNECTION_ATTRIBUTES`` 序列化成字节。"""
    attrs = wlanapi._WLAN_CONNECTION_ATTRIBUTES()
    attrs.isState = state
    assoc = attrs.wlanAssociationAttributes
    _fill_ssid(assoc.dot11Ssid, ssid)
    for offset, byte in enumerate(bssid):
        assoc.dot11Bssid[offset] = byte
    assoc.wlanSignalQuality = quality
    assoc.ulRxRate = rx_kbps
    assoc.ulTxRate = tx_kbps
    return ctypes.string_at(ctypes.byref(attrs), ctypes.sizeof(attrs))


@pytest.fixture
def fake_dll(monkeypatch: pytest.MonkeyPatch) -> _FakeDll:
    """把 ``wlanapi._dll`` 换成假 DLL（模块级私有注入点）。"""
    fake = _FakeDll()
    monkeypatch.setattr(wlanapi, "_dll", lambda: fake)
    return fake


def test_dll_missing_raises_system_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: Any, **kwargs: Any) -> Any:
        raise OSError("找不到 wlanapi.dll")

    monkeypatch.setattr(ctypes, "WinDLL", _boom)
    with pytest.raises(SystemUnavailable, match=r"wlanapi\.dll"):
        wlanapi._load_wlanapi()


def test_open_handle_failure_raises_and_does_not_close(fake_dll: _FakeDll) -> None:
    fake_dll.open_code = 5
    with pytest.raises(SystemUnavailable, match="WlanOpenHandle"):
        wlanapi.wifi_state()
    assert fake_dll.closed == 0


def test_open_handle_closes_when_body_raises(fake_dll: _FakeDll) -> None:
    with pytest.raises(RuntimeError, match="boom"), wlanapi._open_handle():
        raise RuntimeError("boom")
    assert fake_dll.closed == 1


def test_enum_failure_raises_system_unavailable(fake_dll: _FakeDll) -> None:
    fake_dll.enum_code = 87
    with pytest.raises(SystemUnavailable, match="WlanEnumInterfaces"):
        wlanapi.wifi_state()
    with pytest.raises(SystemUnavailable, match="WlanEnumInterfaces"):
        wlanapi.wifi_scan()
    assert fake_dll.closed == 2
    assert fake_dll.freed == []


def test_no_wireless_interface(fake_dll: _FakeDll) -> None:
    assert wlanapi.wifi_state() == WifiState(connected=False)
    assert wlanapi.wifi_scan() == WifiScan(networks=[], available=True)
    assert fake_dll.closed == 2
    assert fake_dll.queries == []


def test_disconnected_interface_is_not_queried(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_DISCONNECTED)]

    state = wlanapi.wifi_state()

    assert state == WifiState(connected=False, interface="WLAN", state="disconnected")
    assert fake_dll.queries == []
    assert fake_dll.closed == 1
    assert len(fake_dll.freed) == 1  # 接口列表已释放


def test_query_invalid_state_means_disconnected(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_CONNECTED)]
    fake_dll.query_results[wlanapi._OPCODE_CURRENT_CONNECTION] = (5023, None)

    state = wlanapi.wifi_state()

    assert state.connected is False
    assert state.interface == "WLAN"
    assert state.state == "disconnected"
    assert len(fake_dll.freed) == 1  # 只有接口列表；失败的查询没有分配内存


def test_query_other_failure_is_reported_in_state(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_CONNECTED)]
    fake_dll.query_results[wlanapi._OPCODE_CURRENT_CONNECTION] = (5, None)

    state = wlanapi.wifi_state()

    assert state.connected is False
    assert state.state is not None
    assert "读取当前连接失败" in state.state


def test_connected_state_from_bss_frequency(fake_dll: _FakeDll) -> None:
    ssid = "家庭网络".encode()
    bssid = b"\xaa\xbb\xcc\xdd\xee\xff"
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_CONNECTED)]
    fake_dll.query_results[wlanapi._OPCODE_CURRENT_CONNECTION] = (
        0,
        _connection_payload(wlanapi._STATE_CONNECTED, ssid, bssid, 88, 866700, 1201000),
    )
    fake_dll.bss_entries = [(ssid, bssid, 88, 5180000)]

    state = wlanapi.wifi_state()

    assert state.connected is True
    assert state.interface == "WLAN"
    assert state.ssid == "家庭网络"
    assert state.bssid == "AA:BB:CC:DD:EE:FF"
    assert state.signal_pct == 88
    assert (state.channel, state.band) == (36, "5GHz")
    assert state.rx_mbps == pytest.approx(866.7)
    assert state.tx_mbps == pytest.approx(1201.0)
    assert state.state == "connected"
    assert wlanapi._OPCODE_CHANNEL_NUMBER not in fake_dll.queries  # 频率优先
    assert fake_dll.closed == 1
    assert len(fake_dll.freed) == 3  # 接口列表 + 连接属性 + BSS 列表


def test_state_prefers_connected_interface(fake_dll: _FakeDll) -> None:
    bssid = bytes(range(6))
    fake_dll.enum_interfaces = [
        (b"\x00" * 16, "WLAN-A", wlanapi._STATE_DISCONNECTED),
        (b"\x11" * 16, "WLAN-B", wlanapi._STATE_CONNECTED),
    ]
    fake_dll.query_results[wlanapi._OPCODE_CURRENT_CONNECTION] = (
        0,
        _connection_payload(wlanapi._STATE_CONNECTED, b"Office", bssid, 60, 100000, 200000),
    )
    fake_dll.bss_entries = [(b"Office", bssid, 60, 2412000)]

    state = wlanapi.wifi_state()

    assert state.connected is True
    assert state.interface == "WLAN-B"
    assert state.ssid == "Office"


def test_connected_state_falls_back_to_channel_number(fake_dll: _FakeDll) -> None:
    bssid = bytes(range(6))
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_CONNECTED)]
    fake_dll.query_results[wlanapi._OPCODE_CURRENT_CONNECTION] = (
        0,
        _connection_payload(wlanapi._STATE_CONNECTED, b"Office", bssid, 60, 100000, 200000),
    )
    fake_dll.query_results[wlanapi._OPCODE_CHANNEL_NUMBER] = (0, struct.pack("<I", 36))
    fake_dll.bss_entries = []  # 拿不到中心频率

    state = wlanapi.wifi_state()

    assert (state.channel, state.band) == (36, "5GHz")
    assert wlanapi._OPCODE_CHANNEL_NUMBER in fake_dll.queries
    assert len(fake_dll.freed) == 4  # 接口 + 连接 + 空 BSS + 信道查询


def test_connected_state_channel_query_failure_is_none(fake_dll: _FakeDll) -> None:
    bssid = bytes(range(6))
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_CONNECTED)]
    fake_dll.query_results[wlanapi._OPCODE_CURRENT_CONNECTION] = (
        0,
        _connection_payload(wlanapi._STATE_CONNECTED, b"Office", bssid, 60, 100000, 200000),
    )
    fake_dll.bss_code = 5
    fake_dll.query_results[wlanapi._OPCODE_CHANNEL_NUMBER] = (5, None)

    state = wlanapi.wifi_state()

    assert state.channel is None
    assert state.band is None


def test_incomplete_connection_data_frees_memory(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_CONNECTED)]
    fake_dll.query_results[wlanapi._OPCODE_CURRENT_CONNECTION] = (0, None)

    state = wlanapi.wifi_state()

    assert state.connected is False
    assert state.state is not None
    assert "数据不完整" in state.state
    assert len(fake_dll.freed) == 2  # 接口列表 + 失败分支仍释放查询指针
    assert 0 in fake_dll.freed


def test_query_channel_number_success_and_null(fake_dll: _FakeDll) -> None:
    guid = wlanapi._GUID()
    fake_dll.query_results[wlanapi._OPCODE_CHANNEL_NUMBER] = (0, struct.pack("<I", 11))
    assert wlanapi._query_channel_number(1, guid) == 11

    fake_dll.query_results[wlanapi._OPCODE_CHANNEL_NUMBER] = (0, None)
    assert wlanapi._query_channel_number(1, guid) is None
    assert 0 in fake_dll.freed


def test_query_channel_number_failure(fake_dll: _FakeDll) -> None:
    fake_dll.query_results[wlanapi._OPCODE_CHANNEL_NUMBER] = (5, None)
    with pytest.raises(wlanapi._WlanCallError, match="channel_number"):
        wlanapi._query_channel_number(1, wlanapi._GUID())


def test_query_bss_frequency_match_miss_empty_and_failure(fake_dll: _FakeDll) -> None:
    guid = wlanapi._GUID()
    first = b"\x01\x02\x03\x04\x05\x06"
    second = b"\x0a\x0b\x0c\x0d\x0e\x0f"
    fake_dll.bss_entries = [(b"A", first, 10, 2412000), (b"B", second, 20, 5180000)]

    assert wlanapi._query_bss_frequency(1, guid, b"B", second) == 5180000
    assert wlanapi._query_bss_frequency(1, guid, b"C", b"\x00" * 6) is None

    fake_dll.bss_entries = []
    assert wlanapi._query_bss_frequency(1, guid, b"A", first) is None

    fake_dll.bss_code = 5
    with pytest.raises(wlanapi._WlanCallError, match="WlanGetNetworkBssList"):
        wlanapi._query_bss_frequency(1, guid, b"A", first)
    assert len(fake_dll.freed) == 3  # 两次列表 + 一次空指针


def test_get_bss_list_success_empty_and_failure(fake_dll: _FakeDll) -> None:
    fake_dll.bss_entries = [(b"A", bytes(range(6)), 10, 2412000)]
    ptr = wlanapi._get_bss_list(1, wlanapi._GUID())
    assert ptr
    fake_dll.WlanFreeMemory(ptr)

    fake_dll.bss_entries = []
    assert wlanapi._get_bss_list(1, wlanapi._GUID()) is None

    fake_dll.bss_code = 87
    with pytest.raises(wlanapi._WlanCallError, match="WlanGetNetworkBssList"):
        wlanapi._get_bss_list(1, wlanapi._GUID())


def test_available_security_mapping_empty_and_failure(fake_dll: _FakeDll) -> None:
    fake_dll.available_entries = [(b"Home", 7, 4), (b"", 0, 0)]
    assert wlanapi._available_security(1, wlanapi._GUID()) == {b"Home": ("WPA2-PSK", "CCMP")}

    fake_dll.available_entries = []
    assert wlanapi._available_security(1, wlanapi._GUID()) == {}

    fake_dll.available_code = 5
    with pytest.raises(wlanapi._WlanCallError, match="WlanGetAvailableNetworkList"):
        wlanapi._available_security(1, wlanapi._GUID())


def test_iter_interface_entries_synthetic() -> None:
    buffer = _build_interface_buffer([(bytes(range(16)), "WLAN-A", 1), (b"\xaa" * 16, "WLAN-B", 4)])
    list_ptr = ctypes.cast(buffer, ctypes.POINTER(wlanapi._WLAN_INTERFACE_INFO_LIST))

    entries = list(wlanapi._iter_interface_entries(list_ptr))

    assert [entry.strInterfaceDescription for entry in entries] == ["WLAN-A", "WLAN-B"]
    assert [entry.isState for entry in entries] == [1, 4]
    assert list(wlanapi._iter_interface_entries(None)) == []


def test_iter_available_entries_synthetic() -> None:
    buffer = _build_available_buffer([(b"Home", 7, 4)])
    list_ptr = ctypes.cast(buffer, ctypes.POINTER(wlanapi._WLAN_AVAILABLE_NETWORK_LIST))

    entries = list(wlanapi._iter_available_entries(list_ptr))

    assert len(entries) == 1
    assert entries[0].dot11Ssid.uSSIDLength == 4
    assert int(entries[0].dot11DefaultAuthAlgorithm) == 7
    assert list(wlanapi._iter_available_entries(None)) == []


def test_make_ssid_caps_length() -> None:
    ssid = wlanapi._make_ssid(b"X" * 40)
    assert ssid.uSSIDLength == 32
    assert bytes(ssid.ucSSID[:3]) == b"XXX"


def test_interface_state_name_unknown() -> None:
    assert wlanapi._interface_state_name(4) == "disconnected"
    assert wlanapi._interface_state_name(99) == "state_99"


def test_decode_ssid_empty_buffer() -> None:
    assert wlanapi._decode_ssid(b"", 4) is None


def test_win_error_falls_back_when_format_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(code: int) -> str:
        raise OSError("FormatError 不可用")

    monkeypatch.setattr(ctypes, "FormatError", _boom)
    assert "未知错误" in wlanapi._win_error(5)


def test_scan_permission_denied_by_wlan_scan(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_DISCONNECTED)]
    fake_dll.scan_code = 5

    scan = wlanapi.wifi_scan()

    assert scan.available is False
    assert scan.networks == []
    assert scan.error is not None
    assert "位置" in scan.error
    assert fake_dll.scan_calls == 1
    assert fake_dll.closed == 1
    assert len(fake_dll.freed) == 2  # 接口列表 + 可用网络空指针


def test_scan_permission_denied_by_bss_list(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_DISCONNECTED)]
    fake_dll.bss_code = 5

    scan = wlanapi.wifi_scan()

    assert scan.available is False
    assert scan.error is not None
    assert "位置" in scan.error
    assert len(fake_dll.freed) == 1  # 只有接口列表


def test_scan_other_failure_is_reported(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_DISCONNECTED)]
    fake_dll.bss_code = 87

    scan = wlanapi.wifi_scan()

    assert scan.available is False
    assert scan.networks == []
    assert scan.error is not None
    assert "WlanGetNetworkBssList" in scan.error


def test_scan_success_with_no_networks(fake_dll: _FakeDll) -> None:
    """扫描可用但周边确实没有网络：available=True、列表为空。"""
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_DISCONNECTED)]

    scan = wlanapi.wifi_scan()

    assert scan == WifiScan(networks=[], available=True)
    assert fake_dll.scan_calls == 1
    assert fake_dll.closed == 1


def test_scan_success_maps_and_sorts_networks(fake_dll: _FakeDll) -> None:
    first = b"\x01\x02\x03\x04\x05\x06"
    second = b"\x0a\x0b\x0c\x0d\x0e\x0f"
    third = b"\x11\x12\x13\x14\x15\x16"
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_DISCONNECTED)]
    fake_dll.bss_entries = [
        (b"Strong", first, 90, 2412000),
        (b"Weak", second, 20, 5180000),
        (b"", third, 10, 5955000),
        (b"Duplicate", first, 99, 2437000),  # 同一 BSSID 只保留第一次
    ]
    fake_dll.available_entries = [(b"Strong", 7, 4), (b"Weak", 1, 0)]

    scan = wlanapi.wifi_scan()

    assert scan.available is True
    assert scan.error is None
    assert [network.ssid for network in scan.networks] == ["Strong", "Weak", None]
    assert [network.signal_pct for network in scan.networks] == [90, 20, 10]

    strong, weak, hidden = scan.networks
    assert strong.bssid == "01:02:03:04:05:06"
    assert (strong.channel, strong.band) == (1, "2.4GHz")
    assert (strong.auth, strong.encryption) == ("WPA2-PSK", "CCMP")
    assert (weak.channel, weak.band) == (36, "5GHz")
    assert (weak.auth, weak.encryption) == ("open", "none")
    assert hidden.bssid == "11:12:13:14:15:16"
    assert (hidden.channel, hidden.band) == (1, "6GHz")
    assert (hidden.auth, hidden.encryption) == (None, None)

    assert fake_dll.closed == 1
    assert len(fake_dll.freed) == 3  # 接口列表 + BSS 列表 + 可用网络列表


def test_scan_security_list_failure_keeps_bss_data(fake_dll: _FakeDll) -> None:
    fake_dll.enum_interfaces = [(bytes(range(16)), "WLAN", wlanapi._STATE_DISCONNECTED)]
    fake_dll.bss_entries = [(b"Home", bytes(range(6)), 50, 2412000)]
    fake_dll.available_code = 5

    scan = wlanapi.wifi_scan()

    assert scan.available is True
    assert len(scan.networks) == 1
    network = scan.networks[0]
    assert network.ssid == "Home"
    assert (network.auth, network.encryption) == (None, None)
    assert network.channel == 1


# ---------------------------------------------------------------------------
# 真机只读验证
# ---------------------------------------------------------------------------


def test_live_wifi_state_is_readonly() -> None:
    """真机只读：不崩即可；无网卡/未连接时 skip 并说明。"""
    try:
        state = wlanapi.wifi_state()
    except SystemUnavailable as exc:
        pytest.skip(f"本机 wlanapi 不可用：{exc}")

    assert isinstance(state, WifiState)
    if not state.connected:
        pytest.skip(f"本机当前未连接 WiFi（只读验证通过，state={state.state!r}）")
    assert state.ssid is not None


def test_live_wifi_scan_is_readonly() -> None:
    """真机只读：扫描不可用时必须给出 error，可用时网络字段应自洽。"""
    try:
        scan = wlanapi.wifi_scan()
    except SystemUnavailable as exc:
        pytest.skip(f"本机 wlanapi 不可用：{exc}")

    assert isinstance(scan, WifiScan)
    if not scan.available:
        assert scan.error
        pytest.skip(f"本机扫描不可用（可能缺位置权限）：{scan.error}")
    for network in scan.networks:
        assert network.signal_pct is None or 0 <= network.signal_pct <= 100
        assert network.band in (None, "2.4GHz", "5GHz", "6GHz")
