"""Windows ICMP hop probes through IP Helper; no raw socket or elevation."""

import ctypes
import ipaddress
import time
from collections import Counter
from ctypes import wintypes


IP_SUCCESS = 0
IP_TTL_EXPIRED_TRANSIT = 11013
IP_REQ_TIMED_OUT = 11010
IP_UNREACHABLE = {11002, 11003, 11004, 11005, 11012, 11018, 11040}
ACCESS_DENIED = {5, 1314}
AF_INET6 = 23


class _IpOptions32(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.c_uint32)]


class _EchoReply32(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32), ("DataSize", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint16), ("Data", ctypes.c_uint32),
                ("Options", _IpOptions32)]


class _SockaddrIn6(ctypes.Structure):
    _fields_ = [("family", ctypes.c_uint16), ("port", ctypes.c_uint16),
                ("flow", ctypes.c_uint32), ("address", ctypes.c_ubyte * 16),
                ("scope", ctypes.c_uint32)]


class _Ipv6AddressEx(ctypes.Structure):
    # The IP Helper reply uses two-byte packing here, unlike sockaddr_in6.
    _pack_ = 2
    _fields_ = [("port", ctypes.c_uint16), ("flow", ctypes.c_uint32),
                ("address", ctypes.c_ubyte * 16), ("scope", ctypes.c_uint32)]


class _EchoReply6(ctypes.Structure):
    _fields_ = [("Address", _Ipv6AddressEx), ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32)]


def _api(ipv6):
    api = ctypes.WinDLL("iphlpapi", use_last_error=True)
    api.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    api.IcmpCloseHandle.restype = wintypes.BOOL
    if ipv6:
        api.Icmp6CreateFile.restype = ctypes.c_void_p
        send = api.Icmp6SendEcho2
        send.argtypes = [ctypes.c_void_p] * 4 + [ctypes.POINTER(_SockaddrIn6)] * 2 + [
            ctypes.c_void_p, ctypes.c_uint16, ctypes.POINTER(_IpOptions32),
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
        api.Icmp6ParseReplies.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        api.Icmp6ParseReplies.restype = ctypes.c_uint32
        handle = api.Icmp6CreateFile()
    else:
        api.IcmpCreateFile.restype = ctypes.c_void_p
        send = api.IcmpSendEcho2
        send.argtypes = [ctypes.c_void_p] * 4 + [ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint16, ctypes.POINTER(_IpOptions32), ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32]
        handle = api.IcmpCreateFile()
    send.restype = ctypes.c_uint32
    if handle in (None, ctypes.c_void_p(-1).value):
        raise PermissionError(ctypes.get_last_error(), "IP Helper ICMP handle unavailable")
    return api, send, handle


def run(peer, result, *, max_hops, probes_per_hop, timeout_s, packet_bytes):
    """Probe only the caller-validated, observed numeric RTP peer."""
    address = ipaddress.ip_address(peer)
    ipv6 = address.version == 6
    api, send, handle = _api(ipv6)
    # 100 bytes includes IPv4/IPv6 and ICMP headers, not just payload.
    payload_size = packet_bytes - (48 if ipv6 else 28)
    payload = ctypes.create_string_buffer(b"V" * payload_size)
    reply_buffer = ctypes.create_string_buffer(512)
    destination = source = None
    if ipv6:
        source = _SockaddrIn6()
        source.family = AF_INET6
        destination = _SockaddrIn6()
        destination.family = AF_INET6
        destination.address[:] = address.packed
    else:
        destination = int.from_bytes(address.packed, "little")
    deadline = time.monotonic() + timeout_s
    hops = []
    reached = timed_out = no_route = False
    try:
        for ttl in range(1, max_hops + 1):
            responders, times = [], []
            sent = 0
            for _ in range(probes_per_hop):
                remaining_ms = int((deadline - time.monotonic()) * 1000)
                if remaining_ms <= 0:
                    timed_out = True
                    break
                options = _IpOptions32(ttl, 0, 0, 0, 0)
                ctypes.memset(reply_buffer, 0, ctypes.sizeof(reply_buffer))
                wait_ms = min(250, remaining_ms)
                if ipv6:
                    count = send(handle, None, None, None, ctypes.byref(source),
                                 ctypes.byref(destination), payload, payload_size,
                                 ctypes.byref(options), reply_buffer,
                                 ctypes.sizeof(reply_buffer), wait_ms)
                    if count:
                        count = api.Icmp6ParseReplies(reply_buffer, ctypes.sizeof(reply_buffer))
                    reply = _EchoReply6.from_buffer(reply_buffer)
                    responder = str(ipaddress.IPv6Address(bytes(reply.Address.address)))
                else:
                    count = send(handle, None, None, None, destination, payload,
                                 payload_size, ctypes.byref(options), reply_buffer,
                                 ctypes.sizeof(reply_buffer), wait_ms)
                    reply = _EchoReply32.from_buffer(reply_buffer)
                    responder = str(ipaddress.IPv4Address(reply.Address.to_bytes(4, "little")))
                sent += 1
                if not count:
                    if ctypes.get_last_error() in ACCESS_DENIED:
                        result.update(status="unavailable", reason="icmp_permission_denied", hops=hops)
                        return result
                    continue
                if reply.Status in (IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT):
                    responders.append(responder)
                    times.append(float(reply.RoundTripTime))
                    reached |= reply.Status == IP_SUCCESS and responder == peer
                elif reply.Status in IP_UNREACHABLE:
                    no_route = True
            if sent:
                hops.append({"ttl": ttl, "address": Counter(responders).most_common(1)[0][0] if responders else None,
                             "sent": sent, "responses": len(responders),
                             "rtt_min_ms": min(times) if times else None,
                             "rtt_avg_ms": round(sum(times) / len(times), 3) if times else None,
                             "rtt_max_ms": max(times) if times else None,
                             "status": "responded" if times else "no_response"})
            if reached or timed_out or no_route:
                break
    finally:
        api.IcmpCloseHandle(handle)
    if no_route:
        result.update(status="unavailable", reason="destination_unreachable", hops=hops)
    elif timed_out:
        result.update(status="unavailable", reason="timeout", hops=hops)
    elif not hops:
        result.update(status="unavailable", reason="no_hops_returned")
    elif not reached:
        result.update(status="unavailable", reason="destination_not_reached", hops=hops)
    else:
        result.update(status="complete", reason=None, hops=hops)
    return result
