"""Local Linux measurements, with explicit kernel-host/container scope."""
import json
import struct
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import threading
import time

_started = time.monotonic()
_lock = threading.Lock()
_samples = {}


def _read(path):
    try:
        return pathlib.Path(path).read_text().strip()
    except (OSError, ValueError):
        return None


def _number(path):
    try:
        return int(_read(path))
    except (TypeError, ValueError):
        return None


def _ratio(used, total):
    return round(min(100, max(0, 100 * used / total)), 1) if total and used is not None else None


def _percent(key, used, total):
    with _lock:
        old = _samples.get(key)
        _samples[key] = (used, total)
    if old and total > old[1] and used >= old[0]:
        return round(min(100, max(0, 100 * (used - old[0]) / (total - old[1]))), 1)
    return None


def _cpuset(value):
    if not value:
        return None
    try:
        return sum(int(part.split('-')[1]) - int(part.split('-')[0]) + 1 if '-' in part else 1 for part in value.split(','))
    except ValueError:
        return None


def system_snapshot(data_path=None):
    if platform.system() == "Windows":
        return _windows_system_snapshot(data_path)
    container = pathlib.Path('/.dockerenv').exists() or pathlib.Path('/run/.containerenv').exists() or any(x in (_read('/proc/1/cgroup') or '') for x in ('docker', 'kubepods', 'containerd'))
    cores = os.cpu_count() or 1
    try:
        cores = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        pass
    mem = {}
    for line in (_read('/proc/meminfo') or '').splitlines():
        try:
            key, rest = line.split(':', 1)
            mem[key] = int(rest.split()[0]) * 1024
        except (ValueError, IndexError):
            pass
    host_total, host_avail = mem.get('MemTotal'), mem.get('MemAvailable')
    host_used = host_total - host_avail if host_total is not None and host_avail is not None else None
    host_memory = {'total_bytes': host_total, 'used_bytes': host_used, 'available_bytes': host_avail, 'percent': _ratio(host_used, host_total)}
    host_cpu = None
    try:
        fields = [int(x) for x in (_read('/proc/stat') or '').splitlines()[0].split()[1:9]]
        total = sum(fields)
        host_cpu = _percent('host_cpu', total - fields[3] - fields[4], total)
    except (IndexError, ValueError):
        pass
    try:
        load = os.getloadavg()[0]
    except (AttributeError, OSError):
        load = None
    total_mem, used_mem, available_mem = host_total, host_used, host_avail
    cpu_percent = host_cpu
    memory_source = 'proc/meminfo'
    cpu_source = 'proc/stat'
    if container:
        max_mem = _number('/sys/fs/cgroup/memory.max') or _number('/sys/fs/cgroup/memory/memory.limit_in_bytes')
        current_mem = _number('/sys/fs/cgroup/memory.current')
        if current_mem is None:
            current_mem = _number('/sys/fs/cgroup/memory/memory.usage_in_bytes')
        if current_mem is not None:
            total_mem = min(max_mem, host_total) if max_mem and host_total else host_total
            used_mem = current_mem
            available_mem = max(0, total_mem - used_mem) if total_mem else None
            memory_source = 'cgroup'
        else:
            total_mem = used_mem = available_mem = None
            memory_source = 'unavailable'
        cpu_max = (_read('/sys/fs/cgroup/cpu.max') or '').split()
        try:
            quota = int(cpu_max[0]) / int(cpu_max[1]) if cpu_max[0] != 'max' else None
        except (ValueError, IndexError, ZeroDivisionError):
            q = _number('/sys/fs/cgroup/cpu/cpu.cfs_quota_us')
            p = _number('/sys/fs/cgroup/cpu/cpu.cfs_period_us')
            quota = q / p if q and q > 0 and p else None
        cpuset = _cpuset(_read('/sys/fs/cgroup/cpuset.cpus.effective') or _read('/sys/fs/cgroup/cpuset/cpuset.cpus'))
        cores = min(cores, quota or cores, cpuset or cores)
        cpu_used = None
        for line in (_read('/sys/fs/cgroup/cpu.stat') or '').splitlines():
            if line.startswith('usage_usec '):
                cpu_used = int(line.split()[1]) / 1000000
        if cpu_used is None:
            v = _number('/sys/fs/cgroup/cpuacct/cpuacct.usage')
            cpu_used = v / 1000000000 if v is not None else None
        cpu_percent = _percent('container_cpu', cpu_used, time.monotonic() * cores) if cpu_used is not None else None
        cpu_source = 'cgroup' if cpu_used is not None else 'unavailable'
    disk = {'total_bytes': None, 'used_bytes': None, 'free_bytes': None, 'percent': None}
    try:
        d = shutil.disk_usage(data_path or '/')
        disk = {'total_bytes': d.total, 'used_bytes': d.used, 'free_bytes': d.free, 'percent': _ratio(d.used, d.total), 'scope': 'filesystem_visible_to_agent', 'path': str(data_path or '/')}
    except OSError:
        pass
    temperature = None
    for path in pathlib.Path('/sys/class/thermal').glob('thermal_zone*/temp'):
        sensor_type = (_read(path.parent / 'type') or '').lower()
        if not any(x in sensor_type for x in ('cpu', 'x86_pkg', 'soc', 'k10temp', 'coretemp')):
            continue
        n = _number(path)
        if n is not None and 0 < n < 150000:
            temperature = n / 1000
            break
    try:
        uptime = float((_read('/proc/uptime') or '').split()[0])
    except (ValueError, IndexError):
        uptime = None
    return {'scope': 'container' if container else 'host', 'cpu': {'percent': cpu_percent, 'available_cores': cores, 'load_1m': load, 'load_scope': 'kernel_host', 'source': cpu_source}, 'memory': {'total_bytes': total_mem, 'used_bytes': used_mem, 'available_bytes': available_mem, 'percent': _ratio(used_mem, total_mem), 'source': memory_source}, 'disk': disk, 'uptime_s': uptime, 'process_uptime_s': round(time.monotonic() - _started), 'temperature_c': temperature, 'temperature_scope': 'kernel_host', 'host': {'scope': 'kernel_host', 'memory': host_memory, 'cpu_percent': host_cpu, 'cpu_count': os.cpu_count(), 'load_1m': load, 'os': platform.platform()}}


def _ip(args):
    try:
        return json.loads(subprocess.run(['ip', '-j'] + args, capture_output=True, text=True, timeout=1, check=True).stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def network_snapshot(cfg=None):
    cfg = cfg or {}
    if platform.system() == "Windows":
        return _windows_network_snapshot(cfg)
    addresses = _ip(['address', 'show'])
    interfaces = [{'name': x.get('ifname'), 'up': 'UP' in x.get('flags', []), 'addresses': [{'family': y.get('family'), 'address': y.get('local'), 'prefixlen': y.get('prefixlen'), 'scope': y.get('scope')} for y in x.get('addr_info', [])]} for x in addresses]
    if not interfaces:
        try:
            interfaces = [{'name': n, 'up': (_read('/sys/class/net/' + n + '/operstate') == 'up'), 'addresses': []} for _, n in socket.if_nameindex()]
        except OSError:
            interfaces = []
        # Native installations may not have iproute2: kernel-only fallback.
        try:
            import fcntl
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for interface in interfaces:
                    try:
                        result = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', interface['name'].encode()[:15]))
                        interface['addresses'].append({'family': 'inet', 'address': socket.inet_ntoa(result[20:24]), 'scope': 'host' if interface['name'] == 'lo' else 'local'})
                    except OSError:
                        pass
        except (ImportError, OSError):
            pass
        for line in (_read('/proc/net/if_inet6') or '').splitlines():
            fields = line.split()
            if len(fields) != 6:
                continue
            for interface in interfaces:
                if interface['name'] == fields[5]:
                    try:
                        interface['addresses'].append({'family': 'inet6', 'address': socket.inet_ntop(socket.AF_INET6, bytes.fromhex(fields[0])), 'prefixlen': int(fields[2], 16), 'scope': {'00': 'global', '20': 'link', '10': 'host'}.get(fields[3], 'local')})
                    except ValueError:
                        pass
    routes = _ip(['route', 'show', 'default']) or _ip(['-6', 'route', 'show', 'default'])
    route = routes[0] if routes else {}
    if not route:
        for line in (_read('/proc/net/route') or '').splitlines()[1:]:
            fields = line.split()
            if len(fields) > 3 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                route = {'dev': fields[0], 'gateway': socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])}
                break
    dns = [line.split()[1] for line in (_read('/etc/resolv.conf') or '').splitlines() if len(line.split()) > 1 and line.split()[0] == 'nameserver']
    container = pathlib.Path('/.dockerenv').exists() or pathlib.Path('/run/.containerenv').exists()
    primary_address = next((a['address'] for i in interfaces if i['name'] == route.get('dev') for a in i['addresses'] if a['family'] == 'inet'), None)
    return {'hostname': socket.gethostname(), 'primary_address': primary_address, 'interfaces': interfaces, 'primary_interface': route.get('dev'), 'gateway': route.get('gateway'), 'dns': dns, 'controller_url': cfg.get('controller_url'), 'management_url': cfg.get('management_url'), 'public_ip': None, 'scope': 'container' if container else 'host'}


def _windows_system_snapshot(data_path=None):
    """Use the qualified Windows psutil wheel; unavailable values stay null."""
    memory = {"total_bytes": None, "used_bytes": None, "available_bytes": None, "percent": None, "source": "unavailable"}
    cpu = {"percent": None, "available_cores": os.cpu_count(), "load_1m": None, "load_scope": "unavailable", "source": "unavailable"}
    disk = {"total_bytes": None, "used_bytes": None, "free_bytes": None, "percent": None, "path": str(data_path or pathlib.Path.home()), "scope": "filesystem_visible_to_agent"}
    uptime = None
    try:
        import psutil
        m = psutil.virtual_memory()
        memory.update(total_bytes=m.total, used_bytes=m.total-m.available, available_bytes=m.available, percent=m.percent, source="Windows GlobalMemoryStatusEx")
        cpu.update(percent=psutil.cpu_percent(interval=None), source="Windows GetSystemTimes")
        uptime = max(0, time.time() - psutil.boot_time())
    except (ImportError, OSError):
        pass
    try:
        d = shutil.disk_usage(data_path or pathlib.Path.home())
        disk.update(total_bytes=d.total, used_bytes=d.used, free_bytes=d.free, percent=_ratio(d.used, d.total))
    except OSError:
        pass
    return {"scope": "host", "cpu": cpu, "memory": memory, "disk": disk,
            "uptime_s": uptime, "process_uptime_s": round(time.monotonic()-_started),
            "temperature_c": None, "temperature_scope": "unavailable",
            "host": {"scope": "host", "os": platform.platform(), "cpu_count": os.cpu_count(), "load_1m": None}}


def _windows_network_snapshot(cfg):
    interfaces = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        for name, entries in psutil.net_if_addrs().items():
            addresses = []
            for entry in entries:
                if entry.family in (socket.AF_INET, socket.AF_INET6):
                    address = entry.address.split("%", 1)[0]
                    addresses.append({"family": "inet" if entry.family == socket.AF_INET else "inet6", "address": address, "scope": "host" if address in ("127.0.0.1", "::1") else "local"})
            interfaces.append({"name": name, "up": bool(stats.get(name) and stats[name].isup), "addresses": addresses})
    except (ImportError, OSError):
        pass
    # Report an observable route to the configured Controller, with no packets
    # transmitted. Multiple interfaces and IPv6 remain visible independently.
    primary = None
    try:
        from urllib.parse import urlsplit
        target = urlsplit(cfg.get("controller_url") or "")
        if target.hostname:
            for family, kind, protocol, _, destination in socket.getaddrinfo(target.hostname, target.port or 443, type=socket.SOCK_DGRAM):
                with socket.socket(family, kind, protocol) as route:
                    try:
                        route.connect(destination)
                        primary = route.getsockname()[0].split("%", 1)[0]
                        break
                    except OSError:
                        pass
    except (OSError, ValueError):
        pass
    primary_interface = next((i["name"] for i in interfaces if any(a["address"] == primary for a in i["addresses"])), None)
    return {"hostname": socket.gethostname(), "primary_address": primary, "interfaces": interfaces,
            "primary_interface": primary_interface, "gateway": None, "dns": [],
            "controller_url": cfg.get("controller_url"), "management_url": None, "public_ip": None,
            "scope": "host"}
