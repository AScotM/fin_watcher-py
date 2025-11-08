#!/usr/bin/env python3

import os
import sys
import time
import json
import socket
import struct
import argparse
import threading
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from enum import Enum
import signal
import re
from datetime import datetime, timedelta

# Constants
DEFAULT_TCP_FILE = "/proc/net/tcp"
DEFAULT_TCP6_FILE = "/proc/net/tcp6"
DEFAULT_WATCH_INTERVAL = 2.0
DEFAULT_RESOLVE_TIMEOUT = 0.2
DEFAULT_MAX_PROCESS_AGE = 5.0
DEFAULT_MAX_CONCURRENT_DNS = 10
MIN_WATCH_INTERVAL = 0.1
MAX_RESOLVE_TIMEOUT = 30.0
MAX_CONCURRENT_DNS_LIMIT = 1000
DNS_CACHE_TTL = 300.0

class TCPState(Enum):
    ESTABLISHED = 1
    SYN_SENT = 2
    SYN_RECV = 3
    FIN_WAIT1 = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11
    NEW_SYN_RECV = 12

TCP_STATES = {
    TCPState.ESTABLISHED: "ESTABLISHED",
    TCPState.SYN_SENT: "SYN_SENT",
    TCPState.SYN_RECV: "SYN_RECV",
    TCPState.FIN_WAIT1: "FIN_WAIT1",
    TCPState.FIN_WAIT2: "FIN_WAIT2",
    TCPState.TIME_WAIT: "TIME_WAIT",
    TCPState.CLOSE: "CLOSE",
    TCPState.CLOSE_WAIT: "CLOSE_WAIT",
    TCPState.LAST_ACK: "LAST_ACK",
    TCPState.LISTEN: "LISTEN",
    TCPState.CLOSING: "CLOSING",
    TCPState.NEW_SYN_RECV: "NEW_SYN_RECV"
}

FIN_STATES = {
    TCPState.FIN_WAIT1, TCPState.FIN_WAIT2, TCPState.TIME_WAIT,
    TCPState.CLOSE_WAIT, TCPState.LAST_ACK, TCPState.CLOSING
}

STATE_COLORS = {
    "ESTABLISHED": "\033[32m{}\033[0m",
    "LISTEN": "\033[34m{}\033[0m",
    "CLOSE": "\033[31m{}\033[0m",
    "TIME_WAIT": "\033[33m{}\033[0m",
    "SYN_SENT": "\033[36m{}\033[0m",
    "SYN_RECV": "\033[36m{}\033[0m",
    "FIN_WAIT1": "\033[35m{}\033[0m",
    "FIN_WAIT2": "\033[35m{}\033[0m",
    "CLOSE_WAIT": "\033[31m{}\033[0m",
    "LAST_ACK": "\033[31m{}\033[0m",
    "CLOSING": "\033[31m{}\033[0m",
    "NEW_SYN_RECV": "\033[36m{}\033[0m",
    "UNKNOWN": "\033[90m{}\033[0m"
}

@dataclass
class ConnectionHistory:
    state: str
    timestamp: datetime
    duration: str = ""
    tx_queue: int = 0
    rx_queue: int = 0

@dataclass
class Socket:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    process: str
    resolved: str = ""
    first_seen: str = ""
    duration: str = ""
    tx_queue: int = 0
    rx_queue: int = 0
    uid: int = 0
    inode: str = ""
    state_changes: int = 0

@dataclass
class FinConnection:
    socket: Socket
    first_seen: datetime
    last_state: str
    state_history: List[ConnectionHistory] = field(default_factory=list)
    total_duration: str = ""
    is_listening: bool = False
    is_established: bool = False
    close_reason: str = ""

@dataclass
class ConnectionStats:
    total: int = 0
    by_state: Dict[str, int] = field(default_factory=dict)
    by_process: Dict[str, int] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    ipv4_count: int = 0
    ipv6_count: int = 0
    fin_connections: int = 0
    established_count: int = 0
    listening_count: int = 0
    state_transitions: int = 0
    active_fin_connections: int = 0

class FinTracker:
    def __init__(self):
        self.connections: Dict[str, FinConnection] = {}
        self.state_history: Dict[str, List[ConnectionHistory]] = {}
        self._lock = threading.RLock()

    def track(self, socket: Socket, tx_queue: int, rx_queue: int) -> None:
        key = f"{socket.local_ip}:{socket.local_port}-{socket.remote_ip}:{socket.remote_port}"
        
        with self._lock:
            now = datetime.now()
            
            if key in self.connections:
                fin_conn = self.connections[key]
                if fin_conn.socket.state != socket.state:
                    duration = self._format_duration(now - fin_conn.last_state_change())
                    fin_conn.state_history.append(ConnectionHistory(
                        state=socket.state,
                        timestamp=now,
                        duration=duration,
                        tx_queue=tx_queue,
                        rx_queue=rx_queue
                    ))
                    fin_conn.last_state = socket.state
                    fin_conn.socket.state_changes += 1
                
                fin_conn.socket.tx_queue = tx_queue
                fin_conn.socket.rx_queue = rx_queue
                fin_conn.socket.state = socket.state
                fin_conn.total_duration = self._format_duration(now - fin_conn.first_seen)
                
                fin_conn.is_listening = socket.state == "LISTEN"
                fin_conn.is_established = socket.state == "ESTABLISHED"
                
                if socket.state in [s.name for s in FIN_STATES]:
                    self._determine_close_reason(fin_conn, socket.state)
            else:
                fin_conn = FinConnection(
                    socket=socket,
                    first_seen=now,
                    last_state=socket.state,
                    state_history=[ConnectionHistory(
                        state=socket.state,
                        timestamp=now,
                        tx_queue=tx_queue,
                        rx_queue=rx_queue
                    )],
                    is_listening=socket.state == "LISTEN",
                    is_established=socket.state == "ESTABLISHED"
                )
                fin_conn.socket.tx_queue = tx_queue
                fin_conn.socket.rx_queue = rx_queue
                fin_conn.socket.state_changes = 1
                
                self.connections[key] = fin_conn

    def _determine_close_reason(self, fin_conn: FinConnection, current_state: str) -> None:
        close_reasons = {
            "FIN_WAIT1": "Local endpoint initiated close (sent FIN)",
            "FIN_WAIT2": "Remote endpoint acknowledged FIN, waiting for remote FIN",
            "TIME_WAIT": "Both ends closed, waiting for lingering packets",
            "CLOSE_WAIT": "Remote endpoint initiated close, waiting for local close",
            "LAST_ACK": "Local endpoint sent FIN, waiting for final ACK",
            "CLOSING": "Both endpoints initiated close simultaneously"
        }
        fin_conn.close_reason = close_reasons.get(current_state, "")

    def get_fin_connection(self, socket: Socket) -> Optional[FinConnection]:
        key = f"{socket.local_ip}:{socket.local_port}-{socket.remote_ip}:{socket.remote_port}"
        with self._lock:
            return self.connections.get(key)

    def get_duration(self, socket: Socket) -> Optional[timedelta]:
        key = f"{socket.local_ip}:{socket.local_port}-{socket.remote_ip}:{socket.remote_port}"
        with self._lock:
            if key in self.connections:
                return datetime.now() - self.connections[key].first_seen
        return None

    def get_all_fin_connections(self) -> List[FinConnection]:
        with self._lock:
            return list(self.connections.values())

    def cleanup(self) -> None:
        with self._lock:
            cutoff = datetime.now() - timedelta(hours=1)
            keys_to_remove = []
            
            for key, fin_conn in self.connections.items():
                if (fin_conn.first_seen < cutoff and 
                    fin_conn.socket.state not in [s.name for s in FIN_STATES]):
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.connections[key]
            
            for key, history in list(self.state_history.items()):
                if history and history[-1].timestamp < cutoff:
                    del self.state_history[key]

    def _format_duration(self, duration: timedelta) -> str:
        total_seconds = duration.total_seconds()
        if total_seconds < 60:
            return f"{total_seconds:.1f}s"
        elif total_seconds < 3600:
            minutes = int(total_seconds // 60)
            seconds = int(total_seconds % 60)
            return f"{minutes}m{seconds}s"
        else:
            hours = int(total_seconds // 3600)
            minutes = int((total_seconds % 3600) // 60)
            return f"{hours}h{minutes}m"

class DNSResolver:
    def __init__(self, ttl: float = DNS_CACHE_TTL):
        self.cache: Dict[str, str] = {}
        self.cache_time: Dict[str, datetime] = {}
        self.ttl = ttl
        self._lock = threading.RLock()

    def lookup(self, ip: str, timeout: float = DEFAULT_RESOLVE_TIMEOUT) -> str:
        with self._lock:
            cached = self.cache.get(ip)
            cache_time = self.cache_time.get(ip)
            
            if cached and cache_time and (datetime.now() - cache_time).total_seconds() <= self.ttl:
                return cached

        try:
            result = socket.gethostbyaddr(ip)[0]
            if result:
                with self._lock:
                    self.cache[ip] = result
                    self.cache_time[ip] = datetime.now()
                return result
        except (socket.herror, socket.gaierror, OSError):
            pass
        
        return ""

    def cleanup(self) -> None:
        with self._lock:
            cutoff = datetime.now() - timedelta(seconds=self.ttl)
            ips_to_remove = [ip for ip, cache_time in self.cache_time.items() if cache_time < cutoff]
            for ip in ips_to_remove:
                del self.cache[ip]
                del self.cache_time[ip]

@dataclass
class Config:
    tcp_file: str = DEFAULT_TCP_FILE
    tcp6_file: str = DEFAULT_TCP6_FILE
    watch_interval: float = DEFAULT_WATCH_INTERVAL
    state: str = ""
    local_ip: str = ""
    remote_ip: str = ""
    port: int = 0
    process: str = ""
    sort_by: str = "state"
    format: str = "table"
    no_color: bool = False
    verbose: bool = False
    show_stats: bool = False
    resolve: bool = False
    resolve_timeout: float = DEFAULT_RESOLVE_TIMEOUT
    summary: bool = False
    max_process_age: float = DEFAULT_MAX_PROCESS_AGE
    max_concurrent_dns: int = DEFAULT_MAX_CONCURRENT_DNS
    watch_fin: bool = False
    show_durations: bool = False
    show_fin_details: bool = False
    show_queue_info: bool = False
    show_state_history: bool = False

class ProcessManager:
    def __init__(self):
        self.cache: Dict[str, str] = {}
        self.last_update: Optional[datetime] = None
        self.updating = False
        self._lock = threading.RLock()

    def get(self, refresh_interval: float) -> Dict[str, str]:
        with self._lock:
            cache_valid = (self.cache and self.last_update and 
                          (datetime.now() - self.last_update).total_seconds() <= refresh_interval and 
                          not self.updating)
            if cache_valid:
                return self.cache.copy()

        return self._build_process_map()

    def _build_process_map(self) -> Dict[str, str]:
        with self._lock:
            self.updating = True

        process_map = {}
        try:
            proc_path = Path("/proc")
            if not proc_path.exists():
                return process_map

            for proc_dir in proc_path.iterdir():
                if not proc_dir.is_dir() or not proc_dir.name.isdigit():
                    continue

                pid = proc_dir.name
                inodes = self._get_socket_inodes(pid)
                process_name = self._get_process_name(pid)

                if process_name:
                    for inode in inodes:
                        process_map[inode] = f"{process_name} ({pid})"

            with self._lock:
                self.cache = process_map
                self.last_update = datetime.now()
                self.updating = False

        except Exception:
            with self._lock:
                self.updating = False

        return process_map

    def _get_socket_inodes(self, pid: str) -> Set[str]:
        inodes = set()
        fd_path = Path(f"/proc/{pid}/fd")
        
        try:
            if not fd_path.exists():
                return inodes
                
            for fd in fd_path.iterdir():
                try:
                    target = fd.readlink()
                    if target and target.startswith("socket:["):
                        inode = target[8:-1]
                        inodes.add(inode)
                except (OSError, ValueError):
                    continue
        except OSError:
            pass
            
        return inodes

    def _get_process_name(self, pid: str) -> str:
        comm_path = Path(f"/proc/{pid}/comm")
        if comm_path.exists():
            try:
                return comm_path.read_text().strip()
            except OSError:
                pass

        cmdline_path = Path(f"/proc/{pid}/cmdline")
        if cmdline_path.exists():
            try:
                cmdline = cmdline_path.read_text().strip()
                if '\x00' in cmdline:
                    cmdline = cmdline.split('\x00')[0]
                return Path(cmdline).name if cmdline else ""
            except OSError:
                pass

        return ""

def safe_path(path: str) -> bool:
    """Check if path is safe to read from /proc filesystem"""
    try:
        # Normalize the path
        normalized = os.path.normpath(path)
        
        # Allow only specific proc net files
        allowed_paths = {
            '/proc/net/tcp',
            '/proc/net/tcp6', 
            '/proc/net/udp',
            '/proc/net/udp6',
            '/proc/net/raw',
            '/proc/net/raw6'
        }
        
        # Check if it's one of the allowed paths or a subpath of /proc/net/
        if normalized in allowed_paths or normalized.startswith('/proc/net/'):
            # Additional security: ensure it doesn't contain path traversal
            if '..' in path or path.startswith('/proc/net/../'):
                return False
            return True
            
        return False
    except (ValueError, RuntimeError):
        return False

def parse_hex_ip_port(s: str, is_ipv6: bool = False) -> Tuple[str, int]:
    parts = s.split(':')
    if is_ipv6:
        if len(parts) < 2:
            raise ValueError(f"Invalid IPv6 format: {s}")
        ip_hex = ''.join(parts[:-1])
        port_hex = parts[-1]
    else:
        if len(parts) != 2:
            raise ValueError(f"Invalid IPv4 format: {s}")
        ip_hex, port_hex = parts

    try:
        ip_bytes = bytes.fromhex(ip_hex)
        ip_bytes = ip_bytes[::-1]
        
        expected_len = 16 if is_ipv6 else 4
        if len(ip_bytes) != expected_len:
            raise ValueError(f"Invalid IP length: got {len(ip_bytes)}, expected {expected_len}")
            
        ip = socket.inet_ntop(socket.AF_INET6 if is_ipv6 else socket.AF_INET, ip_bytes)
        port = int(port_hex, 16)
        return ip, port
    except (ValueError, socket.error) as e:
        raise ValueError(f"Failed to parse IP/port: {e}")

def read_tcp_connections(file_path: str, verbose: bool, is_ipv6: bool, proc_map: Dict[str, str]) -> List[Socket]:
    if not safe_path(file_path):
        raise PermissionError(f"Invalid or unsafe path: {file_path}")

    sockets = []
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []
    except OSError as e:
        raise OSError(f"Failed to read {file_path}: {e}")

    for line_num, line in enumerate(lines[1:], 2):
        line = line.strip()
        if not line:
            continue

        fields = line.split()
        if len(fields) < 10:
            if verbose:
                print(f"WARNING: Skipping malformed line {line_num} in {file_path}", file=sys.stderr)
            continue

        try:
            local_ip, local_port = parse_hex_ip_port(fields[1], is_ipv6)
            remote_ip, remote_port = parse_hex_ip_port(fields[2], is_ipv6)
            
            state_code = int(fields[3], 16)
            state = TCP_STATES.get(TCPState(state_code), f"UNKNOWN({state_code})")
            
            tx_queue = int(fields[4], 16) if len(fields) > 4 else 0
            rx_queue = int(fields[5], 16) if len(fields) > 5 else 0
            uid = int(fields[7]) if len(fields) > 7 else 0
            inode = fields[9] if len(fields) > 9 else ""
            
            process = proc_map.get(inode, "Unknown")

            sockets.append(Socket(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                state=state,
                process=process,
                tx_queue=tx_queue,
                rx_queue=rx_queue,
                uid=uid,
                inode=inode
            ))
            
        except (ValueError, IndexError) as e:
            if verbose:
                print(f"WARNING: Line {line_num}: {e}", file=sys.stderr)
            continue

    return sockets

def read_all_connections(tcp_file: str, tcp6_file: str, verbose: bool, max_process_age: float, proc_manager: ProcessManager) -> Tuple[List[Socket], List[str]]:
    sockets = []
    errors = []
    proc_map = proc_manager.get(max_process_age)

    for file_path, is_ipv6 in [(tcp_file, False), (tcp6_file, True)]:
        try:
            if not os.path.exists(file_path):
                if verbose:
                    print(f"WARNING: File {file_path} does not exist", file=sys.stderr)
                continue
                
            connections = read_tcp_connections(file_path, verbose, is_ipv6, proc_map)
            sockets.extend(connections)
        except Exception as e:
            errors.append(str(e))

    return sockets, errors

def validate_filters(state: str, local_ip: str, remote_ip: str) -> None:
    valid_states = set(TCP_STATES.values())
    if state and state.upper() not in valid_states:
        raise ValueError(f"Invalid state filter: {state}")

    if local_ip:
        try:
            if '/' in local_ip:
                socket.inet_ntoa(socket.inet_aton(local_ip.split('/')[0]))
            else:
                socket.inet_ntoa(socket.inet_aton(local_ip))
        except OSError:
            raise ValueError(f"Invalid local IP filter: {local_ip}")

    if remote_ip:
        try:
            if '/' in remote_ip:
                socket.inet_ntoa(socket.inet_aton(remote_ip.split('/')[0]))
            else:
                socket.inet_ntoa(socket.inet_aton(remote_ip))
        except OSError:
            raise ValueError(f"Invalid remote IP filter: {remote_ip}")

def validate_config(cfg: Config) -> None:
    if cfg.watch_interval < 0:
        raise ValueError("Watch interval cannot be negative")
    
    if cfg.max_process_age <= 0:
        raise ValueError("Max process age must be positive")
    
    if cfg.resolve_timeout < 0:
        raise ValueError("Resolve timeout cannot be negative")
    
    if cfg.resolve_timeout > MAX_RESOLVE_TIMEOUT:
        raise ValueError(f"Resolve timeout too long, max {MAX_RESOLVE_TIMEOUT}")
    
    if cfg.max_concurrent_dns <= 0:
        raise ValueError("Max concurrent DNS must be positive")
    
    if cfg.max_concurrent_dns > MAX_CONCURRENT_DNS_LIMIT:
        raise ValueError(f"Max concurrent DNS too high, max {MAX_CONCURRENT_DNS_LIMIT}")
    
    valid_sort = {"state", "local_ip", "remote_ip", "port", "process", "duration"}
    if cfg.sort_by not in valid_sort:
        raise ValueError(f"Sort must be one of: {', '.join(valid_sort)}")
    
    valid_formats = {"table", "json"}
    if cfg.format not in valid_formats:
        raise ValueError("Format must be one of: table, json")
    
    # Only validate path safety, not existence (files might not exist on all systems)
    if not safe_path(cfg.tcp_file) or not safe_path(cfg.tcp6_file):
        raise ValueError("Invalid TCP file path - path must be under /proc/net/")
    
    validate_filters(cfg.state, cfg.local_ip, cfg.remote_ip)

def filter_sockets(sockets: List[Socket], state: str, local_ip: str, remote_ip: str, process: str, port: int, watch_fin: bool) -> List[Socket]:
    if not any([state, local_ip, remote_ip, process, port, watch_fin]):
        return sockets

    filtered = []
    fin_state_names = {s.name for s in FIN_STATES}

    for s in sockets:
        if state and s.state != state.upper():
            continue
            
        if local_ip:
            if '/' in local_ip:
                # Simple subnet matching (basic implementation)
                if not s.local_ip.startswith(local_ip.split('/')[0].rsplit('.', 1)[0]):
                    continue
            elif s.local_ip != local_ip:
                continue
                
        if remote_ip:
            if '/' in remote_ip:
                if not s.remote_ip.startswith(remote_ip.split('/')[0].rsplit('.', 1)[0]):
                    continue
            elif s.remote_ip != remote_ip:
                continue
                
        if port and s.local_port != port and s.remote_port != port:
            continue
            
        if process and process.lower() not in s.process.lower():
            continue
            
        if watch_fin and s.state not in fin_state_names:
            continue
            
        filtered.append(s)

    return filtered

def sort_sockets(sockets: List[Socket], sort_by: str, fin_tracker: FinTracker) -> List[Socket]:
    if sort_by == "state":
        return sorted(sockets, key=lambda x: x.state)
    elif sort_by == "local_ip":
        return sorted(sockets, key=lambda x: x.local_ip)
    elif sort_by == "remote_ip":
        return sorted(sockets, key=lambda x: x.remote_ip)
    elif sort_by == "port":
        return sorted(sockets, key=lambda x: (x.local_port, x.remote_port))
    elif sort_by == "process":
        return sorted(sockets, key=lambda x: x.process)
    elif sort_by == "duration":
        return sorted(sockets, key=lambda x: fin_tracker.get_duration(x) or timedelta(0), reverse=True)
    else:
        return sockets

def calculate_stats(sockets: List[Socket], fin_tracker: FinTracker) -> ConnectionStats:
    stats = ConnectionStats(
        by_state={},
        by_process={},
        total=len(sockets)
    )

    fin_connections = fin_tracker.get_all_fin_connections()
    stats.active_fin_connections = len(fin_connections)

    for socket in sockets:
        stats.by_state[socket.state] = stats.by_state.get(socket.state, 0) + 1
        stats.by_process[socket.process] = stats.by_process.get(socket.process, 0) + 1

        if socket.state in [s.name for s in FIN_STATES]:
            stats.fin_connections += 1

        if socket.state == "ESTABLISHED":
            stats.established_count += 1

        if socket.state == "LISTEN":
            stats.listening_count += 1

        if ':' in socket.local_ip:
            stats.ipv6_count += 1
        else:
            stats.ipv4_count += 1

    for fin_conn in fin_connections:
        stats.state_transitions += len(fin_conn.state_history)

    return stats

def resolve_hosts(sockets: List[Socket], timeout: float, max_concurrent: int, dns_resolver: DNSResolver) -> None:
    if not sockets or max_concurrent <= 0:
        return

    max_concurrent = min(max_concurrent, len(sockets))

    def resolve_socket(s: Socket) -> Socket:
        ip = s.remote_ip
        if ip in ("0.0.0.0", "::", "*"):
            return s

        resolved = dns_resolver.lookup(ip, timeout)
        if resolved:
            s.resolved = resolved
        return s

    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        futures = [executor.submit(resolve_socket, s) for s in sockets]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                pass

def display_fin_connection_details(fin_conn: FinConnection, no_color: bool) -> None:
    print(f"\n🔍 FIN Connection Details:")
    print(f"   Local:  {fin_conn.socket.local_ip}:{fin_conn.socket.local_port}")
    print(f"   Remote: {fin_conn.socket.remote_ip}:{fin_conn.socket.remote_port}")
    print(f"   Process: {fin_conn.socket.process}")
    print(f"   Current State: {fin_conn.socket.state}")
    print(f"   First Seen: {fin_conn.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Total Duration: {fin_conn.total_duration}")
    print(f"   State Changes: {fin_conn.socket.state_changes}")
    
    if fin_conn.close_reason:
        print(f"   Close Reason: {fin_conn.close_reason}")
    
    print(f"   Queue Info: TX={fin_conn.socket.tx_queue}, RX={fin_conn.socket.rx_queue}")
    print(f"   Flags: Listening={fin_conn.is_listening}, Established={fin_conn.is_established}")
    
    if len(fin_conn.state_history) > 1:
        print(f"\n   State History:")
        for i, history in enumerate(fin_conn.state_history, 1):
            state = history.state
            if not no_color and state in STATE_COLORS:
                state = STATE_COLORS[state].format(state)
            line = f"     {i:2d}. {state} at {history.timestamp.strftime('%H:%M:%S')}"
            if history.duration:
                line += f" (duration: {history.duration})"
            if history.tx_queue > 0 or history.rx_queue > 0:
                line += f" [TX:{history.tx_queue} RX:{history.rx_queue}]"
            print(line)
    print("─" * 80)

def format_duration(duration: timedelta) -> str:
    total_seconds = duration.total_seconds()
    if total_seconds < 60:
        return f"{total_seconds:.1f}s"
    elif total_seconds < 3600:
        minutes = int(total_seconds // 60)
        seconds = int(total_seconds % 60)
        return f"{minutes}m{seconds}s"
    else:
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        return f"{hours}h{minutes}m"

def display_connections(sockets: List[Socket], format: str, no_color: bool, watch_mode: bool, show_stats: bool, 
                       show_durations: bool, show_fin_details: bool, show_queue_info: bool, 
                       show_state_history: bool, fin_tracker: FinTracker) -> None:
    if not sockets:
        print("No active TCP connections found")
        return

    if watch_mode and format == "table":
        stats = calculate_stats(sockets, fin_tracker)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        stats_info = ""
        if show_stats:
            established = stats.by_state.get("ESTABLISHED", 0)
            listen = stats.by_state.get("LISTEN", 0)
            fin = stats.fin_connections
            stats_info = f" [EST:{established} LISTEN:{listen} FIN:{fin}]"
        print(f"{timestamp} - {stats.total} connections{stats_info}")
        return

    if format == "json":
        output = {"connections": []}
        for s in sockets:
            conn_dict = {
                "local_ip": s.local_ip,
                "local_port": s.local_port,
                "remote_ip": s.remote_ip,
                "remote_port": s.remote_port,
                "state": s.state,
                "process": s.process
            }
            if s.resolved:
                conn_dict["resolved"] = s.resolved
            if s.duration:
                conn_dict["duration"] = s.duration
            if s.first_seen:
                conn_dict["first_seen"] = s.first_seen
            output["connections"].append(conn_dict)

        if show_fin_details or show_stats:
            output["statistics"] = {
                "total": stats.total,
                "by_state": stats.by_state,
                "by_process": stats.by_process,
                "timestamp": stats.timestamp.isoformat(),
                "ipv4_count": stats.ipv4_count,
                "ipv6_count": stats.ipv6_count,
                "fin_connections": stats.fin_connections,
                "established_count": stats.established_count,
                "listening_count": stats.listening_count,
                "state_transitions": stats.state_transitions,
                "active_fin_connections": stats.active_fin_connections
            }
            
        print(json.dumps(output, indent=2))
        return

    headers = ["State", "Local Address", "Remote Address", "Process"]
    widths = [len(h) for h in headers]

    if show_durations:
        headers.append("Duration")
        widths.append(len("Duration"))
    
    if show_queue_info:
        headers.append("TX/RX")
        widths.append(len("TX/RX"))
    
    if show_state_history:
        headers.append("Changes")
        widths.append(len("Changes"))

    for s in sockets:
        widths[0] = max(widths[0], len(s.state))
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        widths[1] = max(widths[1], len(local_addr))
        widths[2] = max(widths[2], len(remote_addr))
        widths[3] = max(widths[3], len(s.process))
        
        if show_durations:
            widths[4] = max(widths[4], len(s.duration))
        if show_queue_info:
            queue_info = f"{s.tx_queue}/{s.rx_queue}"
            widths[5] = max(widths[5], len(queue_info))
        if show_state_history:
            changes = str(s.state_changes)
            widths[6] = max(widths[6], len(changes))

    print("\nACTIVE TCP CONNECTIONS:")
    header_format = "".join(f"%-{w}s " for w in widths)
    print(header_format % tuple(headers))
    
    total_width = sum(widths) + len(widths) - 1
    print("-" * total_width)

    displayed_fin_conns = set()
    
    for s in sockets:
        state = s.state
        if not no_color and state in STATE_COLORS:
            state = STATE_COLORS[state].format(state)
            
        local_addr = f"{s.local_ip}:{s.local_port}"
        remote_addr = f"{s.remote_ip}:{s.remote_port}"
        process = s.process
        if s.resolved:
            process = f"{process} [{s.resolved}]"

        fields = [state, local_addr, remote_addr, process]
        
        if show_durations:
            fields.append(s.duration)
        if show_queue_info:
            fields.append(f"{s.tx_queue}/{s.rx_queue}")
        if show_state_history:
            fields.append(str(s.state_changes))

        row_format = "".join(f"%-{w}s " for w in widths[:len(fields)])
        print(row_format % tuple(fields))
        
        if show_fin_details and s.state in [state.name for state in FIN_STATES]:
            key = f"{s.local_ip}:{s.local_port}-{s.remote_ip}:{s.remote_port}"
            if key not in displayed_fin_conns:
                fin_conn = fin_tracker.get_fin_connection(s)
                if fin_conn:
                    display_fin_connection_details(fin_conn, no_color)
                    displayed_fin_conns.add(key)

def display_summary(sockets: List[Socket], fin_tracker: FinTracker, no_color: bool) -> None:
    stats = calculate_stats(sockets, fin_tracker)

    print(f"\n📊 TCP CONNECTION SUMMARY:")
    print(f"   Total connections: {stats.total}")
    print(f"   IPv4 connections: {stats.ipv4_count}")
    print(f"   IPv6 connections: {stats.ipv6_count}")
    print(f"   Established connections: {stats.established_count}")
    print(f"   Listening connections: {stats.listening_count}")
    print(f"   FIN state connections: {stats.fin_connections}")
    print(f"   Active FIN tracked: {stats.active_fin_connections}")
    print(f"   Total state transitions: {stats.state_transitions}")
    print(f"   Timestamp: {stats.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

    print("\n   By State:")
    state_counts = sorted(stats.by_state.items(), key=lambda x: x[1], reverse=True)
    for state, count in state_counts:
        colored_state = state
        if not no_color and state in STATE_COLORS:
            colored_state = STATE_COLORS[state].format(state)
        print(f"     {colored_state:<15}: {count}")

    print("\n   Top Processes:")
    process_counts = sorted(stats.by_process.items(), key=lambda x: x[1], reverse=True)[:10]
    for process, count in process_counts:
        print(f"     {process:<30}: {count}")
    
    if stats.active_fin_connections > 0:
        print(f"\n   FIN Connection States:")
        fin_conns = fin_tracker.get_all_fin_connections()
        fin_states = {}
        for conn in fin_conns:
            fin_states[conn.socket.state] = fin_states.get(conn.socket.state, 0) + 1
        for state, count in fin_states.items():
            print(f"     {state:<15}: {count}")

def clear_screen() -> None:
    os.system('clear' if os.name == 'posix' else 'cls')

@contextmanager
def signal_handler():
    stop_event = threading.Event()
    
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        stop_event.set()
    
    original_handlers = {}
    for sig in [signal.SIGINT, signal.SIGTERM]:
        original_handlers[sig] = signal.signal(sig, signal_handler)
    
    try:
        yield stop_event
    finally:
        for sig, handler in original_handlers.items():
            signal.signal(sig, handler)

def load_config(filename: str) -> Config:
    if not safe_path(filename):
        raise PermissionError(f"Invalid config path: {filename}")

    with open(filename, 'r') as f:
        data = json.load(f)
    
    config = Config(**data)
    return config

def check_file_accessibility(*files: str) -> None:
    """Check if files are accessible, but don't fail if they don't exist"""
    for f in files:
        if not safe_path(f):
            raise PermissionError(f"Invalid or unsafe path: {f}")
        if os.path.exists(f):
            try:
                with open(f, 'r'):
                    pass
            except PermissionError as e:
                raise PermissionError(f"Need root privileges for {f}: {e}")

def process_cycle(cfg: Config, proc_manager: ProcessManager, fin_tracker: FinTracker, dns_resolver: DNSResolver) -> None:
    sockets, errors = read_all_connections(cfg.tcp_file, cfg.tcp6_file, cfg.verbose, cfg.max_process_age, proc_manager)
    
    for error in errors:
        print(f"WARNING: {error}", file=sys.stderr)
    
    if not sockets and len(errors) == 2:
        print("WARNING: No TCP connections found - files may be empty or inaccessible", file=sys.stderr)
        return

    filtered_sockets = filter_sockets(sockets, cfg.state, cfg.local_ip, cfg.remote_ip, cfg.process, cfg.port, cfg.watch_fin)

    for s in filtered_sockets:
        fin_tracker.track(s, s.tx_queue, s.rx_queue)
        
        duration = fin_tracker.get_duration(s)
        if duration:
            s.duration = format_duration(duration)
            s.first_seen = (datetime.now() - duration).strftime("%H:%M:%S")
        
        fin_conn = fin_tracker.get_fin_connection(s)
        if fin_conn:
            s.state_changes = fin_conn.socket.state_changes

    sorted_sockets = sort_sockets(filtered_sockets, cfg.sort_by, fin_tracker)

    if cfg.resolve:
        resolve_hosts(sorted_sockets, cfg.resolve_timeout, cfg.max_concurrent_dns, dns_resolver)

    if cfg.summary:
        display_summary(sorted_sockets, fin_tracker, cfg.no_color)
    else:
        display_connections(sorted_sockets, cfg.format, cfg.no_color, cfg.watch_interval > 0, 
                           cfg.show_stats, cfg.show_durations, cfg.show_fin_details, 
                           cfg.show_queue_info, cfg.show_state_history, fin_tracker)

def run_application(cfg: Config) -> None:
    proc_manager = ProcessManager()
    fin_tracker = FinTracker()
    dns_resolver = DNSResolver()

    with signal_handler() as stop_event:
        if cfg.watch_interval > 0:
            mode = "all connections" if not cfg.watch_fin else "FIN state connections"
            print(f"Monitoring TCP {mode} every {cfg.watch_interval}s. Press Ctrl+C to stop.")
            if cfg.show_fin_details:
                print("FIN connection details enabled - showing state history and close reasons")

        last_run = datetime.now()
        
        while not stop_event.is_set():
            if cfg.watch_interval > 0 and cfg.watch_interval < MIN_WATCH_INTERVAL:
                time_since_last = (datetime.now() - last_run).total_seconds()
                if time_since_last < MIN_WATCH_INTERVAL:
                    time.sleep(MIN_WATCH_INTERVAL - time_since_last)

            if cfg.watch_interval > 0:
                clear_screen()

            process_cycle(cfg, proc_manager, fin_tracker, dns_resolver)

            if cfg.watch_interval <= 0:
                break

            last_run = datetime.now()
            
            try:
                stop_event.wait(cfg.watch_interval)
            except KeyboardInterrupt:
                break

        fin_tracker.cleanup()
        dns_resolver.cleanup()

def main():
    if os.name != 'posix' or not os.path.exists('/proc'):
        print("This program requires Linux /proc filesystem", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description="TCP Connection Monitor")
    parser.add_argument("--tcp-file", default=DEFAULT_TCP_FILE, help="Path to TCP file")
    parser.add_argument("--tcp6-file", default=DEFAULT_TCP6_FILE, help="Path to TCP6 file")
    parser.add_argument("--watch", type=float, default=DEFAULT_WATCH_INTERVAL, help="Refresh interval")
    parser.add_argument("--state", help="Filter by state (ESTABLISHED, LISTEN, ...)")
    parser.add_argument("--local-ip", help="Filter by local IP or subnet")
    parser.add_argument("--remote-ip", help="Filter by remote IP or subnet")
    parser.add_argument("--port", type=int, help="Filter by local or remote port")
    parser.add_argument("--process", help="Filter by process substring")
    parser.add_argument("--sort", default="state", help="Sort by: state, local_ip, remote_ip, port, process, duration")
    parser.add_argument("--format", default="table", help="Output format: table, json")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--resolve", action="store_true", help="Resolve remote IPs to hostnames")
    parser.add_argument("--resolve-timeout", type=float, default=DEFAULT_RESOLVE_TIMEOUT, help="DNS resolve timeout")
    parser.add_argument("--max-dns", type=int, default=DEFAULT_MAX_CONCURRENT_DNS, help="Maximum concurrent DNS lookups")
    parser.add_argument("--stats", action="store_true", help="Show statistics in output")
    parser.add_argument("--summary", action="store_true", help="Show summary only")
    parser.add_argument("--config", help="Configuration file (JSON)")
    parser.add_argument("--max-process-age", type=float, default=DEFAULT_MAX_PROCESS_AGE, help="Maximum age of process cache")
    parser.add_argument("--watch-fin", action="store_true", help="Watch only FIN state connections")
    parser.add_argument("--show-durations", action="store_true", help="Show connection durations")
    parser.add_argument("--show-fin-details", action="store_true", help="Show detailed FIN connection information")
    parser.add_argument("--show-queue", action="store_true", help="Show TX/RX queue information")
    parser.add_argument("--show-state-history", action="store_true", help="Show state change history")
    
    args = parser.parse_args()

    try:
        if args.config:
            config = load_config(args.config)
        else:
            config = Config(
                tcp_file=args.tcp_file,
                tcp6_file=args.tcp6_file,
                watch_interval=args.watch,
                state=args.state,
                local_ip=args.local_ip,
                remote_ip=args.remote_ip,
                port=args.port,
                process=args.process,
                sort_by=args.sort,
                format=args.format,
                no_color=args.no_color,
                verbose=args.verbose,
                show_stats=args.stats,
                resolve=args.resolve,
                resolve_timeout=args.resolve_timeout,
                summary=args.summary,
                max_process_age=args.max_process_age,
                max_concurrent_dns=args.max_dns,
                watch_fin=args.watch_fin,
                show_durations=args.show_durations,
                show_fin_details=args.show_fin_details,
                show_queue_info=args.show_queue,
                show_state_history=args.show_state_history
            )

        validate_config(config)
        check_file_accessibility(config.tcp_file, config.tcp6_file)
        run_application(config)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
