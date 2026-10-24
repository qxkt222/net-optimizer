# -*- coding: utf-8 -*-
"""WLAN 状态与周边扫描 —— 直接调用 ``wlanapi.dll``，不再解析 ``netsh`` 文本。

本模块是 :class:`netopt.system.api.SystemApi` 的 WiFi 实现细节：

- :func:`wifi_state`：``WlanOpenHandle`` → ``WlanEnumInterfaces`` →
  ``WlanQueryInterface``（``current_connection``）读取当前连接；
- :func:`wifi_scan``：``WlanScan`` + ``WlanGetNetworkBssList`` 读取周边 BSS。

失败语义：

- DLL 缺失、``WlanOpenHandle`` 失败、枚举接口失败 → 抛
  :class:`netopt.system.api.SystemUnavailable`；
- 当前连接读取失败（句柄本身正常）→ 返回 ``WifiState(connected=False)``，
  原因写进 ``state``；
- 扫描被位置权限限制 → 返回 ``WifiScan(available=False, error=...)``，不抛；
- 没有无线网卡 → ``WifiState(connected=False)`` / ``WifiScan(networks=[])``。

所有由 wlanapi 分配的内存（接口列表、连接属性、BSS 列表）都在 ``finally``
里用 ``WlanFreeMemory`` 释放，句柄用 ``WlanCloseHandle`` 关闭。

约定：不调用 ``netsh``、不启动子进程；只读，不改任何系统配置。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wintypes
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from netopt.domain.models import WifiNetwork, WifiScan, WifiState
from netopt.system.api import SystemUnavailable

# ---------------------------------------------------------------------------
# Win32 常量
# ---------------------------------------------------------------------------

_ERROR_SUCCESS = 0
_ERROR_ACCESS_DENIED = 5
_ERROR_INVALID_STATE = 5023
_ERROR_UNEXPECTED = -1

_WLAN_API_VERSION_2_0 = 2

#: ``WLAN_INTF_OPCODE``：当前连接 / 信道号（wlanapi.h 中按枚举顺序赋值）
_OPCODE_CURRENT_CONNECTION = 7
_OPCODE_CHANNEL_NUMBER = 8

#: ``DOT11_BSS_TYPE_ANY``
_DOT11_BSS_TYPE_ANY = 3

_DOT11_SSID_MAX_LENGTH = 32
_WLAN_MAX_NAME_LENGTH = 256
_WLAN_MAX_PHY_TYPE_NUMBER = 8
_DOT11_RATE_SET_MAX_LENGTH = 126

#: ``WLAN_INTERFACE_STATE``
_STATE_NOT_READY = 0
_STATE_CONNECTED = 1
_STATE_AD_HOC = 2
_STATE_DISCONNECTING = 3
_STATE_DISCONNECTED = 4
_STATE_ASSOCIATING = 5
_STATE_DISCOVERING = 6
_STATE_AUTHENTICATING = 7

_INTERFACE_STATE_NAMES = {
    _STATE_NOT_READY: "not_ready",
    _STATE_CONNECTED: "connected",
    _STATE_AD_HOC: "ad_hoc",
    _STATE_DISCONNECTING: "disconnecting",
    _STATE_DISCONNECTED: "disconnected",
    _STATE_ASSOCIATING: "associating",
    _STATE_DISCOVERING: "discovering",
    _STATE_AUTHENTICATING: "authenticating",
}

#: ``DOT11_AUTH_ALGORITHM``（值见 wlantypes.h）
_AUTH_NAMES = {
    1: "open",
    2: "shared",
    3: "WPA",
    4: "WPA-PSK",
    5: "WPA-none",
    6: "WPA2-Enterprise",
    7: "WPA2-PSK",
    8: "WPA3-Enterprise-192",
    9: "WPA3-SAE",
    10: "OWE",
    11: "WPA3-Enterprise",
}

#: ``DOT11_CIPHER_ALGORITHM``（值见 wlantypes.h）
_CIPHER_NAMES = {
    0: "none",
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP",
    5: "WEP-104",
    6: "BIP",
    8: "GCMP",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
    0x100: "group",
    0x101: "WEP",
}

#: 扫描被位置权限拦截时给用户的说明（Win11 中桌面应用单独授权）
_SCAN_PERMISSION_HINT = (
    "周边 WiFi 扫描被 Windows 拒绝：当前进程没有位置权限。"
    "请在「设置 → 隐私和安全性 → 位置」中开启「位置服务」，"
    "并允许「桌面应用访问你的位置」，然后重试。"
)


# ---------------------------------------------------------------------------
# Win32 结构体（布局已对照 Windows SDK 10.0.26100 的 wlanapi.h / wlantypes.h）
# ---------------------------------------------------------------------------


class _GUID(ctypes.Structure):
    """Win32 ``GUID``。"""

    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _DOT11_SSID(ctypes.Structure):
    """``DOT11_SSID``：长度 + 定长 32 字节 SSID。"""

    _fields_ = [
        ("uSSIDLength", wintypes.ULONG),
        ("ucSSID", ctypes.c_ubyte * _DOT11_SSID_MAX_LENGTH),
    ]


class _WLAN_RATE_SET(ctypes.Structure):
    """``WLAN_RATE_SET``。"""

    _fields_ = [
        ("uRateSetLength", wintypes.ULONG),
        ("usRateSet", ctypes.c_ushort * _DOT11_RATE_SET_MAX_LENGTH),
    ]


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    """``WLAN_INTERFACE_INFO``：接口 GUID、描述、状态。"""

    _fields_ = [
        ("InterfaceGuid", _GUID),
        ("strInterfaceDescription", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
        ("isState", ctypes.c_int),
    ]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    """``WLAN_INTERFACE_INFO_LIST``：变长数组，头部之后紧跟条目。"""

    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1),
    ]


class _WLAN_ASSOCIATION_ATTRIBUTES(ctypes.Structure):
    """``WLAN_ASSOCIATION_ATTRIBUTES``：SSID/BSSID/信号/速率（kbps）。"""

    _fields_ = [
        ("dot11Ssid", _DOT11_SSID),
        ("dot11BssType", ctypes.c_int),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11PhyType", ctypes.c_int),
        ("uDot11PhyIndex", wintypes.ULONG),
        ("wlanSignalQuality", wintypes.ULONG),
        ("ulRxRate", wintypes.ULONG),
        ("ulTxRate", wintypes.ULONG),
    ]


class _WLAN_SECURITY_ATTRIBUTES(ctypes.Structure):
    """``WLAN_SECURITY_ATTRIBUTES``。"""

    _fields_ = [
        ("bSecurityEnabled", wintypes.BOOL),
        ("bOneXEnabled", wintypes.BOOL),
        ("dot11AuthAlgorithm", ctypes.c_int),
        ("dot11CipherAlgorithm", ctypes.c_int),
    ]


class _WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    """``WLAN_CONNECTION_ATTRIBUTES``：``current_connection`` 查询的返回体。"""

    _fields_ = [
        ("isState", ctypes.c_int),
        ("wlanConnectionMode", ctypes.c_int),
        ("strProfileName", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
        ("wlanAssociationAttributes", _WLAN_ASSOCIATION_ATTRIBUTES),
        ("wlanSecurityAttributes", _WLAN_SECURITY_ATTRIBUTES),
    ]


class _WLAN_AVAILABLE_NETWORK(ctypes.Structure):
    """``WLAN_AVAILABLE_NETWORK``：只有默认认证/加密方式，没有信道。"""

    _fields_ = [
        ("strProfileName", ctypes.c_wchar * _WLAN_MAX_NAME_LENGTH),
        ("dot11Ssid", _DOT11_SSID),
        ("dot11BssType", ctypes.c_int),
        ("uNumberOfBssids", wintypes.ULONG),
        ("bNetworkConnectable", wintypes.BOOL),
        ("wlanNotConnectableReason", wintypes.DWORD),
        ("uNumberOfPhyTypes", wintypes.ULONG),
        ("dot11PhyTypes", ctypes.c_int * _WLAN_MAX_PHY_TYPE_NUMBER),
        ("bMorePhyTypes", wintypes.BOOL),
        ("wlanSignalQuality", wintypes.ULONG),
        ("bSecurityEnabled", wintypes.BOOL),
        ("dot11DefaultAuthAlgorithm", ctypes.c_int),
        ("dot11DefaultCipherAlgorithm", ctypes.c_int),
        ("dwFlags", wintypes.DWORD),
        ("dwReserved", wintypes.DWORD),
    ]


class _WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
    """``WLAN_AVAILABLE_NETWORK_LIST``。"""

    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("Network", _WLAN_AVAILABLE_NETWORK * 1),
    ]


class _WLAN_BSS_ENTRY(ctypes.Structure):
    """``WLAN_BSS_ENTRY``：一个 BSS 的 SSID/BSSID/链路质量/中心频率。

    注意：SDK 头文件里 BSS 条目用的是 ``uLinkQuality``（0–100），
    不是连接属性里的 ``wlanSignalQuality``；两者语义相同但字段名不同。
    """

    _fields_ = [
        ("dot11Ssid", _DOT11_SSID),
        ("uPhyId", wintypes.ULONG),
        ("dot11Bssid", ctypes.c_ubyte * 6),
        ("dot11BssType", ctypes.c_int),
        ("dot11BssPhyType", ctypes.c_int),
        ("lRssi", ctypes.c_long),
        ("uLinkQuality", wintypes.ULONG),
        ("bInRegDomain", ctypes.c_ubyte),
        ("usBeaconPeriod", ctypes.c_ushort),
        ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong),
        ("usCapabilityInformation", ctypes.c_ushort),
        ("ulChCenterFrequency", wintypes.ULONG),
        ("wlanRateSet", _WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG),
        ("ulIeSize", wintypes.ULONG),
    ]


class _WLAN_BSS_LIST(ctypes.Structure):
    """``WLAN_BSS_LIST``：变长 BSS 条目数组。"""

    _fields_ = [
        ("dwTotalSize", wintypes.DWORD),
        ("dwNumberOfItems", wintypes.DWORD),
        ("wlanBssEntries", _WLAN_BSS_ENTRY * 1),
    ]


# ---------------------------------------------------------------------------
# 错误与 DLL 装载
# ---------------------------------------------------------------------------


class _WlanCallError(RuntimeError):
    """单次 wlanapi 调用返回非 0 错误码。"""

    def __init__(self, api: str, code: int) -> None:
        self.api = api
        self.code = code
        self.message = f"{api} 失败：{_win_error(code)}"
        super().__init__(self.message)


def _win_error(code: int) -> str:
    """把 Win32 错误码转成 ``WinError N（系统说明）``。"""
    try:
        detail = ctypes.FormatError(code)
    except (OSError, ValueError):
        detail = ""
    detail = detail.strip() or "未知错误"
    return f"WinError {code}（{detail}）"


def _load_wlanapi() -> Any:
    """加载 ``wlanapi.dll`` 并声明函数原型；失败抛 ``SystemUnavailable``。"""
    try:
        dll = ctypes.WinDLL("wlanapi", use_last_error=True)
        dll.WlanOpenHandle.argtypes = [
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.HANDLE),
        ]
        dll.WlanOpenHandle.restype = wintypes.DWORD
        dll.WlanCloseHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        dll.WlanCloseHandle.restype = wintypes.DWORD
        dll.WlanEnumInterfaces.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        dll.WlanEnumInterfaces.restype = wintypes.DWORD
        dll.WlanQueryInterface.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_GUID),
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_int),
        ]
        dll.WlanQueryInterface.restype = wintypes.DWORD
        dll.WlanScan.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_GUID),
            ctypes.POINTER(_DOT11_SSID),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        dll.WlanScan.restype = wintypes.DWORD
        dll.WlanGetNetworkBssList.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_GUID),
            ctypes.POINTER(_DOT11_SSID),
            ctypes.c_int,
            wintypes.BOOL,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        dll.WlanGetNetworkBssList.restype = wintypes.DWORD
        dll.WlanGetAvailableNetworkList.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_GUID),
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        dll.WlanGetAvailableNetworkList.restype = wintypes.DWORD
        dll.WlanFreeMemory.argtypes = [ctypes.c_void_p]
        dll.WlanFreeMemory.restype = None
    except (OSError, AttributeError) as exc:
        raise SystemUnavailable(f"无法加载 wlanapi.dll：{exc}") from exc
    return dll


@lru_cache(maxsize=1)
def _dll() -> Any:
    """进程内复用已声明的 ``wlanapi.dll``。"""
    return _load_wlanapi()


@contextmanager
def _open_handle() -> Iterator[wintypes.HANDLE]:
    """打开 WLAN 客户端句柄，退出时保证 ``WlanCloseHandle``。"""
    dll = _dll()
    handle = wintypes.HANDLE()
    negotiated = wintypes.DWORD()
    code = dll.WlanOpenHandle(
        _WLAN_API_VERSION_2_0, None, ctypes.byref(negotiated), ctypes.byref(handle)
    )
    if code != _ERROR_SUCCESS:
        raise SystemUnavailable(f"WlanOpenHandle 失败：{_win_error(code)}")
    try:
        yield handle
    finally:
        dll.WlanCloseHandle(handle, None)


# ---------------------------------------------------------------------------
# 纯换算函数（可单测，不碰 DLL）
# ---------------------------------------------------------------------------


def _decode_ssid(raw: bytes, length: int) -> str | None:
    """把 ``ucSSID`` 前 ``length`` 字节按 UTF-8 解码；空 SSID 返回 ``None``。"""
    if length <= 0:
        return None
    capped = min(length, _DOT11_SSID_MAX_LENGTH, len(raw))
    if capped <= 0:
        return None
    return raw[:capped].decode("utf-8", errors="replace")


def _format_bssid(raw: bytes) -> str:
    """把 6 字节 MAC 格式化成 ``AA:BB:CC:DD:EE:FF``。"""
    return ":".join(f"{byte:02X}" for byte in raw[:6])


def _signal_pct(quality: int) -> int:
    """把信号质量裁到 0–100（wlanapi 正常就返回 0–100，防御越界值）。"""
    return max(0, min(100, int(quality)))


def _channel_and_band(freq_mhz: int) -> tuple[int | None, str | None]:
    """由中心频率（MHz）换算信道与频段；未知频段返回 ``(None, None)``。

    换算式与任务书一致：2.4G ``(f-2407)//5``、5G ``(f-5000)//5``、
    6G ``(f-5950)//5``。
    """
    if 2412 <= freq_mhz <= 2484:
        return (freq_mhz - 2407) // 5, "2.4GHz"
    if 5180 <= freq_mhz <= 5825:
        return (freq_mhz - 5000) // 5, "5GHz"
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5, "6GHz"
    return None, None


def _band_from_channel(channel: int) -> str | None:
    """没有中心频率时按信道号兜底推断频段。

    6GHz 信道号与 2.4/5GHz 有重叠，这里只在明显区间内下结论；
    1–14 默认按 2.4GHz 处理，这是无频率信息时最常见的解释。
    """
    if 1 <= channel <= 14:
        return "2.4GHz"
    if 32 <= channel <= 177:
        return "5GHz"
    if 178 <= channel <= 233:
        return "6GHz"
    return None


def _kbps_to_mbps(kbps: int) -> float:
    """速率由 kbps 换算成 Mbps。"""
    return kbps / 1000.0


def _auth_name(value: int) -> str | None:
    """``DOT11_AUTH_ALGORITHM`` 转可读名称；未知值返回 ``None``。"""
    return _AUTH_NAMES.get(value)


def _cipher_name(value: int) -> str | None:
    """``DOT11_CIPHER_ALGORITHM`` 转可读名称；未知值返回 ``None``。"""
    return _CIPHER_NAMES.get(value)


def _interface_state_name(state: int) -> str:
    """``WLAN_INTERFACE_STATE`` 转稳定的小写名称。"""
    return _INTERFACE_STATE_NAMES.get(state, f"state_{state}")


# ---------------------------------------------------------------------------
# 变长列表遍历（用地址算术，测试可用合成缓冲区构造）
# ---------------------------------------------------------------------------


def _iter_interface_entries(list_ptr: Any) -> Iterator[_WLAN_INTERFACE_INFO]:
    """遍历 ``WLAN_INTERFACE_INFO_LIST`` 的条目（空指针返回空迭代）。"""
    if not list_ptr:
        return
    base = ctypes.addressof(list_ptr.contents) + _WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
    size = ctypes.sizeof(_WLAN_INTERFACE_INFO)
    for index in range(int(list_ptr.contents.dwNumberOfItems)):
        yield _WLAN_INTERFACE_INFO.from_address(base + index * size)


def _iter_available_entries(list_ptr: Any) -> Iterator[_WLAN_AVAILABLE_NETWORK]:
    """遍历 ``WLAN_AVAILABLE_NETWORK_LIST`` 的条目。"""
    if not list_ptr:
        return
    base = ctypes.addressof(list_ptr.contents) + _WLAN_AVAILABLE_NETWORK_LIST.Network.offset
    size = ctypes.sizeof(_WLAN_AVAILABLE_NETWORK)
    for index in range(int(list_ptr.contents.dwNumberOfItems)):
        yield _WLAN_AVAILABLE_NETWORK.from_address(base + index * size)


def _iter_bss_entries(list_ptr: Any) -> Iterator[_WLAN_BSS_ENTRY]:
    """遍历 ``WLAN_BSS_LIST`` 的条目。

    ``WLAN_BSS_LIST`` 在头文件里声明成 ``wlanBssEntries[1]``，ctypes 的定长
    数组会对下标做边界检查，所以这里用「头部地址 + 字段偏移 + 条目大小」的
    地址算术，而不是 ``list.contents.wlanBssEntries[i]``。
    """
    if not list_ptr:
        return
    base = ctypes.addressof(list_ptr.contents) + _WLAN_BSS_LIST.wlanBssEntries.offset
    size = ctypes.sizeof(_WLAN_BSS_ENTRY)
    for index in range(int(list_ptr.contents.dwNumberOfItems)):
        yield _WLAN_BSS_ENTRY.from_address(base + index * size)


# ---------------------------------------------------------------------------
# 内部读取
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Interface:
    """枚举到的一块无线接口（GUID 已复制，不依赖列表内存）。"""

    guid: _GUID
    description: str
    state: int


def _enum_interfaces(handle: wintypes.HANDLE) -> list[_Interface]:
    """枚举无线接口；返回列表副本后释放原生内存。"""
    dll = _dll()
    ptr = ctypes.c_void_p()
    code = dll.WlanEnumInterfaces(handle, None, ctypes.byref(ptr))
    if code != _ERROR_SUCCESS:
        raise _WlanCallError("WlanEnumInterfaces", code)
    try:
        if not ptr.value:
            return []
        list_ptr = ctypes.cast(ptr, ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST))
        interfaces: list[_Interface] = []
        for info in _iter_interface_entries(list_ptr):
            raw_guid = ctypes.string_at(ctypes.byref(info.InterfaceGuid), ctypes.sizeof(_GUID))
            interfaces.append(
                _Interface(
                    guid=_GUID.from_buffer_copy(raw_guid),
                    description=str(info.strInterfaceDescription),
                    state=int(info.isState),
                )
            )
        return interfaces
    finally:
        dll.WlanFreeMemory(ptr)


def _query_current_connection(handle: wintypes.HANDLE, guid: _GUID) -> _WLAN_CONNECTION_ATTRIBUTES:
    """查询当前连接属性，并把数据复制出原生内存后再释放。"""
    dll = _dll()
    size = wintypes.DWORD()
    data = ctypes.c_void_p()
    value_type = ctypes.c_int()
    code = dll.WlanQueryInterface(
        handle,
        ctypes.byref(guid),
        _OPCODE_CURRENT_CONNECTION,
        None,
        ctypes.byref(size),
        ctypes.byref(data),
        ctypes.byref(value_type),
    )
    if code != _ERROR_SUCCESS:
        raise _WlanCallError("WlanQueryInterface(current_connection)", code)
    try:
        if not data.value or size.value < ctypes.sizeof(_WLAN_CONNECTION_ATTRIBUTES):
            raise _WlanCallError(
                "WlanQueryInterface(current_connection) 返回的数据不完整", _ERROR_UNEXPECTED
            )
        raw = ctypes.string_at(data.value, ctypes.sizeof(_WLAN_CONNECTION_ATTRIBUTES))
        return _WLAN_CONNECTION_ATTRIBUTES.from_buffer_copy(raw)
    finally:
        dll.WlanFreeMemory(data)


def _query_channel_number(handle: wintypes.HANDLE, guid: _GUID) -> int | None:
    """查询当前信道号；读取失败时抛 ``_WlanCallError``。"""
    dll = _dll()
    size = wintypes.DWORD()
    data = ctypes.c_void_p()
    value_type = ctypes.c_int()
    code = dll.WlanQueryInterface(
        handle,
        ctypes.byref(guid),
        _OPCODE_CHANNEL_NUMBER,
        None,
        ctypes.byref(size),
        ctypes.byref(data),
        ctypes.byref(value_type),
    )
    if code != _ERROR_SUCCESS:
        raise _WlanCallError("WlanQueryInterface(channel_number)", code)
    try:
        if not data.value:
            return None
        return int(ctypes.c_uint.from_address(data.value).value)
    finally:
        dll.WlanFreeMemory(data)


def _make_ssid(raw: bytes) -> _DOT11_SSID:
    """构造用于查询的 ``DOT11_SSID``。"""
    ssid = _DOT11_SSID()
    length = min(len(raw), _DOT11_SSID_MAX_LENGTH)
    ssid.uSSIDLength = length
    for index in range(length):
        ssid.ucSSID[index] = raw[index]
    return ssid


def _query_bss_frequency(
    handle: wintypes.HANDLE, guid: _GUID, raw_ssid: bytes, bssid: bytes
) -> int | None:
    """查当前连接所在 BSS 的中心频率（kHz）；权限受限时抛 ``_WlanCallError``。"""
    dll = _dll()
    ssid = _make_ssid(raw_ssid)
    ptr = ctypes.c_void_p()
    code = dll.WlanGetNetworkBssList(
        handle,
        ctypes.byref(guid),
        ctypes.byref(ssid),
        _DOT11_BSS_TYPE_ANY,
        False,
        None,
        ctypes.byref(ptr),
    )
    if code != _ERROR_SUCCESS:
        raise _WlanCallError("WlanGetNetworkBssList", code)
    try:
        if not ptr.value:
            return None
        list_ptr = ctypes.cast(ptr, ctypes.POINTER(_WLAN_BSS_LIST))
        for entry in _iter_bss_entries(list_ptr):
            if bytes(entry.dot11Bssid) == bssid:
                return int(entry.ulChCenterFrequency)
        return None
    finally:
        dll.WlanFreeMemory(ptr)


def _request_scan(handle: wintypes.HANDLE, guid: _GUID) -> int:
    """异步触发一次扫描，返回原始错误码（0 表示已提交）。"""
    dll = _dll()
    return int(dll.WlanScan(handle, ctypes.byref(guid), None, None, None))


def _get_bss_list(handle: wintypes.HANDLE, guid: _GUID) -> Any:
    """取缓存/刚扫到的 BSS 列表；调用方负责 ``WlanFreeMemory``。"""
    dll = _dll()
    ptr = ctypes.c_void_p()
    code = dll.WlanGetNetworkBssList(
        handle,
        ctypes.byref(guid),
        None,
        _DOT11_BSS_TYPE_ANY,
        False,
        None,
        ctypes.byref(ptr),
    )
    if code != _ERROR_SUCCESS:
        raise _WlanCallError("WlanGetNetworkBssList", code)
    return ctypes.cast(ptr, ctypes.POINTER(_WLAN_BSS_LIST)) if ptr.value else None


def _available_security(
    handle: wintypes.HANDLE, guid: _GUID
) -> dict[bytes, tuple[str | None, str | None]]:
    """读取可用网络的默认认证/加密方式，按 SSID 字节索引。

    ``WLAN_BSS_ENTRY`` 本身不带认证/加密字段，这里用可用网络列表补上；
    该调用失败（例如权限问题）只返回空映射，不影响 BSS 本身的数据。
    """
    dll = _dll()
    ptr = ctypes.c_void_p()
    code = dll.WlanGetAvailableNetworkList(handle, ctypes.byref(guid), 0, None, ctypes.byref(ptr))
    if code != _ERROR_SUCCESS:
        raise _WlanCallError("WlanGetAvailableNetworkList", code)
    try:
        if not ptr.value:
            return {}
        list_ptr = ctypes.cast(ptr, ctypes.POINTER(_WLAN_AVAILABLE_NETWORK_LIST))
        security: dict[bytes, tuple[str | None, str | None]] = {}
        for entry in _iter_available_entries(list_ptr):
            length = int(entry.dot11Ssid.uSSIDLength)
            raw = bytes(entry.dot11Ssid.ucSSID)[:length]
            if not raw:
                continue
            security[raw] = (
                _auth_name(int(entry.dot11DefaultAuthAlgorithm)),
                _cipher_name(int(entry.dot11DefaultCipherAlgorithm)),
            )
        return security
    finally:
        dll.WlanFreeMemory(ptr)


# ---------------------------------------------------------------------------
# 数据转换
# ---------------------------------------------------------------------------


def _bss_to_network(
    entry: _WLAN_BSS_ENTRY,
    security: dict[bytes, tuple[str | None, str | None]],
) -> WifiNetwork:
    """把一条 ``WLAN_BSS_ENTRY`` 转成 :class:`WifiNetwork`。"""
    length = int(entry.dot11Ssid.uSSIDLength)
    raw_ssid = bytes(entry.dot11Ssid.ucSSID)
    ssid = _decode_ssid(raw_ssid, length)
    freq_mhz = int(entry.ulChCenterFrequency) // 1000
    channel, band = _channel_and_band(freq_mhz)
    auth, encryption = security.get(raw_ssid[:length], (None, None))
    return WifiNetwork(
        ssid=ssid,
        bssid=_format_bssid(bytes(entry.dot11Bssid)),
        signal_pct=_signal_pct(int(entry.uLinkQuality)),
        channel=channel,
        band=band,
        auth=auth,
        encryption=encryption,
    )


def _connection_to_state(
    handle: wintypes.HANDLE, interface: _Interface, attrs: _WLAN_CONNECTION_ATTRIBUTES
) -> WifiState:
    """把 ``WLAN_CONNECTION_ATTRIBUTES`` 转成 :class:`WifiState`。

    信道/频段优先用 BSS 列表里的中心频率换算；拿不到时退回
    ``channel_number`` 查询，再按信道号兜底推断频段。
    """
    assoc = attrs.wlanAssociationAttributes
    length = int(assoc.dot11Ssid.uSSIDLength)
    raw_ssid = bytes(assoc.dot11Ssid.ucSSID)
    raw_bssid = bytes(assoc.dot11Bssid)
    ssid = _decode_ssid(raw_ssid, length)

    freq_khz: int | None = None
    try:
        freq_khz = _query_bss_frequency(handle, interface.guid, raw_ssid[:length], raw_bssid)
    except _WlanCallError:
        freq_khz = None

    channel: int | None = None
    band: str | None = None
    if freq_khz:
        channel, band = _channel_and_band(freq_khz // 1000)
    if channel is None:
        try:
            channel = _query_channel_number(handle, interface.guid)
        except _WlanCallError:
            channel = None
        if channel is not None:
            band = _band_from_channel(channel)

    connected = int(attrs.isState) in (_STATE_CONNECTED, _STATE_AD_HOC)
    return WifiState(
        connected=connected,
        interface=interface.description,
        ssid=ssid,
        bssid=_format_bssid(raw_bssid),
        signal_pct=_signal_pct(int(assoc.wlanSignalQuality)),
        channel=channel,
        band=band,
        rx_mbps=_kbps_to_mbps(int(assoc.ulRxRate)),
        tx_mbps=_kbps_to_mbps(int(assoc.ulTxRate)),
        state=_interface_state_name(int(attrs.isState)),
    )


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------


def wifi_state() -> WifiState:
    """读取当前 WLAN 连接状态。

    没有无线网卡或未连接时返回 ``WifiState(connected=False)``；当前连接
    读取失败（句柄正常）也返回未连接，并把原因写进 ``state``。只有 DLL
    缺失 / 打开句柄 / 枚举接口失败才抛 :class:`SystemUnavailable`。
    """
    with _open_handle() as handle:
        try:
            interfaces = _enum_interfaces(handle)
        except _WlanCallError as exc:
            raise SystemUnavailable(exc.message) from exc
        if not interfaces:
            return WifiState(connected=False)

        first = interfaces[0]
        disconnected = WifiState(
            connected=False,
            interface=first.description,
            state=_interface_state_name(first.state),
        )
        for interface in interfaces:
            if interface.state not in (_STATE_CONNECTED, _STATE_AD_HOC):
                continue
            try:
                attrs = _query_current_connection(handle, interface.guid)
            except _WlanCallError as exc:
                if exc.code == _ERROR_INVALID_STATE:
                    return WifiState(
                        connected=False,
                        interface=interface.description,
                        state=_interface_state_name(_STATE_DISCONNECTED),
                    )
                return WifiState(
                    connected=False,
                    interface=interface.description,
                    state=f"读取当前连接失败：{exc.message}",
                )
            return _connection_to_state(handle, interface, attrs)
        return disconnected


def wifi_scan() -> WifiScan:
    """扫描周边 WiFi。

    没有无线网卡时返回 ``WifiScan(networks=[], available=True)``；扫描被
    位置权限限制时返回 ``available=False`` 并在 ``error`` 说明开启方式，
    **不抛异常**。只有 DLL / 句柄 / 枚举接口失败才抛 ``SystemUnavailable``。
    """
    with _open_handle() as handle:
        try:
            interfaces = _enum_interfaces(handle)
        except _WlanCallError as exc:
            raise SystemUnavailable(exc.message) from exc
        if not interfaces:
            return WifiScan(networks=[], available=True)

        found: dict[str, WifiNetwork] = {}
        failures: list[str] = []
        permission_denied = False
        for interface in interfaces:
            scan_code = _request_scan(handle, interface.guid)
            if scan_code == _ERROR_ACCESS_DENIED:
                permission_denied = True
            try:
                bss_ptr = _get_bss_list(handle, interface.guid)
            except _WlanCallError as exc:
                if exc.code == _ERROR_ACCESS_DENIED:
                    permission_denied = True
                else:
                    failures.append(f"{interface.description}：{exc.message}")
                continue
            try:
                security: dict[bytes, tuple[str | None, str | None]] = {}
                try:
                    security = _available_security(handle, interface.guid)
                except _WlanCallError:
                    security = {}
                for entry in _iter_bss_entries(bss_ptr):
                    network = _bss_to_network(entry, security)
                    key = network.bssid or f"ssid:{network.ssid}"
                    found.setdefault(key, network)
            finally:
                if bss_ptr:
                    _dll().WlanFreeMemory(bss_ptr)

        networks = sorted(
            found.values(), key=lambda item: (-(item.signal_pct or 0), item.ssid or "")
        )
        if networks:
            return WifiScan(networks=networks, available=True)
        if permission_denied:
            return WifiScan(
                networks=[],
                available=False,
                error=f"{_SCAN_PERMISSION_HINT}（{_win_error(_ERROR_ACCESS_DENIED)}）",
            )
        if failures:
            return WifiScan(networks=[], available=False, error="；".join(failures))
        return WifiScan(networks=[], available=True)


__all__ = ["wifi_scan", "wifi_state"]
