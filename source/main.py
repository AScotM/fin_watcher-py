#!/usr/bin/env python3

import argparse
import collections
import concurrent.futures
import dataclasses
import datetime
import enum
import ipaddress
import json
import os
import pathlib
import pwd
import re
import subprocess
import signal
import socket
import statistics
import sys
import threading
import time
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

VERSION = "2.1.0"
TCP4 = "/proc/net/tcp"
TCP6 = "/proc/net/tcp6"
SOCKET_PATTERN = re.compile(r"^socket:\[(\d+)\]$")
STATE_NAMES = {
    1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
    5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
    9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"
}
FIN_STATES = frozenset({"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE_WAIT", "LAST_ACK", "CLOSING"})
COLORS = {
    "ESTABLISHED": "\033[32m", "LISTEN": "\033[34m", "SYN_SENT": "\033[36m",
    "SYN_RECV": "\033[36m", "FIN_WAIT1": "\033[35m", "FIN_WAIT2": "\033[35m",
    "TIME_WAIT": "\033[33m", "CLOSE_WAIT": "\033[31m", "LAST_ACK": "\033[31m",
    "CLOSING": "\033[31m", "CLOSE": "\033[90m"
}
RESET = "\033[0m"


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def format_seconds(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m{int(seconds % 60):02d}s"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h{int((seconds % 3600) // 60):02d}m"
    return f"{int(seconds // 86400)}d{int((seconds % 86400) // 3600):02d}h"


def decode_endpoint(value: str, family: int) -> Tuple[str, int]:
    address_hex, separator, port_hex = value.partition(":")
    if not separator:
        raise ValueError("endpoint has no port separator")
    address = bytes.fromhex(address_hex)
    if family == socket.AF_INET:
        if len(address) != 4:
            raise ValueError("invalid IPv4 endpoint length")
        address = address[::-1]
    elif family == socket.AF_INET6:
        if len(address) != 16:
            raise ValueError("invalid IPv6 endpoint length")
        address = b"".join(address[i:i + 4][::-1] for i in range(0, 16, 4))
    else:
        raise ValueError("unsupported address family")
    port = int(port_hex, 16)
    if not 0 <= port <= 65535:
        raise ValueError("port outside valid range")
    return socket.inet_ntop(family, address), port


def endpoint_text(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def parse_network(value: str) -> ipaddress._BaseNetwork:
    return ipaddress.ip_network(value, strict=False)


@dataclasses.dataclass(frozen=True)
class SocketRecord:
    family: int
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    state_code: int
    tx_queue: int
    rx_queue: int
    uid: int
    inode: int
    timer: int
    retransmits: int
    process: str = "Unknown"
    pid: Optional[int] = None
    hostname: str = ""

    @property
    def tuple_key(self) -> Tuple[Any, ...]:
        return (self.family, self.local_ip, self.local_port, self.remote_ip, self.remote_port)

    @property
    def key(self) -> Tuple[Any, ...]:
        return (self.tuple_key, self.inode) if self.inode else (self.tuple_key, 0)

    @property
    def local(self) -> str:
        return endpoint_text(self.local_ip, self.local_port)

    @property
    def remote(self) -> str:
        return endpoint_text(self.remote_ip, self.remote_port)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "family": "IPv6" if self.family == socket.AF_INET6 else "IPv4",
            "local_ip": self.local_ip, "local_port": self.local_port,
            "remote_ip": self.remote_ip, "remote_port": self.remote_port,
            "state": self.state, "state_code": self.state_code,
            "tx_queue": self.tx_queue, "rx_queue": self.rx_queue,
            "uid": self.uid, "inode": self.inode,
            "timer": self.timer, "retransmits": self.retransmits,
            "process": self.process, "pid": self.pid, "hostname": self.hostname
        }


@dataclasses.dataclass(frozen=True)
class StateEvent:
    timestamp: str
    monotonic: float
    previous: Optional[str]
    current: str
    kind: str
    elapsed: float

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp, "previous": self.previous,
            "current": self.current, "kind": self.kind,
            "elapsed_seconds": round(self.elapsed, 3)
        }


@dataclasses.dataclass
class TrackedConnection:
    record: SocketRecord
    first_seen: float
    last_seen: float
    first_seen_at: str
    last_seen_at: str
    events: Deque[StateEvent]
    transitions: int = 0
    observed_fin: bool = False
    disappeared: bool = False
    closed_at: Optional[str] = None
    disappeared_reason: str = ""
    last_state_change: float = 0.0

    def age(self, now: float) -> float:
        return max(0.0, now - self.first_seen)

    def state_age(self, now: float) -> float:
        return max(0.0, now - self.last_state_change)

    def as_dict(self, now: float, history: bool = False) -> Dict[str, Any]:
        result = self.record.as_dict()
        result.update({
            "first_seen": self.first_seen_at, "last_seen": self.last_seen_at,
            "age_seconds": round(self.age(now), 3),
            "state_age_seconds": round(self.state_age(now), 3),
            "transitions": self.transitions, "observed_fin": self.observed_fin,
            "disappeared": self.disappeared, "closed_at": self.closed_at,
            "disappeared_reason": self.disappeared_reason
        })
        if history:
            result["history"] = [event.as_dict() for event in self.events]
        return result


@dataclasses.dataclass
class Snapshot:
    records: List[SocketRecord]
    timestamp: str
    monotonic: float
    errors: List[str]
    malformed: int = 0
    truncated: bool = False


@dataclasses.dataclass
class CycleResult:
    snapshot: Snapshot
    active: List[TrackedConnection]
    appeared: List[TrackedConnection]
    changed: List[TrackedConnection]
    disappeared: List[TrackedConnection]
    counts: Dict[str, int]
    total_tracked: int
    total_disappeared: int


class ProcReader:
    def __init__(self, tcp_file: str = TCP4, tcp6_file: str = TCP6, max_connections: int = 100000):
        self.tcp_file = tcp_file
        self.tcp6_file = tcp6_file
        self.max_connections = max_connections

    @staticmethod
    def parse_line(line: str, family: int) -> SocketRecord:
        fields = line.split()
        if len(fields) < 10:
            raise ValueError("short TCP record")
        local_ip, local_port = decode_endpoint(fields[1], family)
        remote_ip, remote_port = decode_endpoint(fields[2], family)
        state_code = int(fields[3], 16)
        queue_parts = fields[4].split(":")
        if len(queue_parts) != 2:
            raise ValueError("invalid TX/RX queue encoding")
        tx_queue, rx_queue = (int(part, 16) for part in queue_parts)
        timer_parts = fields[5].split(":")
        timer = int(timer_parts[0], 16)
        retransmits = int(fields[6], 16)
        uid = int(fields[7])
        inode = int(fields[9])
        return SocketRecord(
            family=family, local_ip=local_ip, local_port=local_port,
            remote_ip=remote_ip, remote_port=remote_port,
            state=STATE_NAMES.get(state_code, f"UNKNOWN({state_code:02X})"),
            state_code=state_code, tx_queue=tx_queue, rx_queue=rx_queue,
            uid=uid, inode=inode, timer=timer, retransmits=retransmits
        )

    def read(self) -> Snapshot:
        records: List[SocketRecord] = []
        errors: List[str] = []
        malformed = 0
        truncated = False
        for filename, family in ((self.tcp_file, socket.AF_INET), (self.tcp6_file, socket.AF_INET6)):
            try:
                with open(filename, "r", encoding="ascii", errors="replace") as handle:
                    next(handle, None)
                    for line_number, line in enumerate(handle, 2):
                        if len(records) >= self.max_connections:
                            truncated = True
                            break
                        if not line.strip():
                            continue
                        try:
                            records.append(self.parse_line(line, family))
                        except (ValueError, IndexError) as exc:
                            malformed += 1
                            if malformed <= 5:
                                errors.append(f"{filename}:{line_number}: {exc}")
            except FileNotFoundError:
                if filename == self.tcp_file:
                    errors.append(f"missing required TCP table: {filename}")
            except OSError as exc:
                errors.append(f"cannot read {filename}: {exc}")
        return Snapshot(records, utc_now(), time.monotonic(), errors, malformed, truncated)


class ProcessResolver:
    def __init__(self, refresh_seconds: float = 5.0, proc_root: str = "/proc"):
        self.refresh_seconds = refresh_seconds
        self.proc_root = pathlib.Path(proc_root)
        self._map: Dict[int, Tuple[str, int]] = {}
        self._updated = -float("inf")
        self._lock = threading.RLock()

    def _scan(self) -> Dict[int, Tuple[str, int]]:
        mapping: Dict[int, Tuple[str, int]] = {}
        try:
            processes = list(self.proc_root.iterdir())
        except OSError:
            return mapping
        for directory in processes:
            if not directory.name.isdigit():
                continue
            pid = int(directory.name)
            try:
                name = (directory / "comm").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                name = str(pid)
            try:
                descriptors = (directory / "fd").iterdir()
                for descriptor in descriptors:
                    try:
                        target = os.readlink(descriptor)
                    except OSError:
                        continue
                    match = SOCKET_PATTERN.fullmatch(target)
                    if match:
                        mapping.setdefault(int(match.group(1)), (name, pid))
            except OSError:
                continue
        return mapping

    def resolve(self, records: Sequence[SocketRecord], now: float) -> List[SocketRecord]:
        with self._lock:
            if now - self._updated >= self.refresh_seconds:
                self._map = self._scan()
                self._updated = now
            mapping = self._map
            return [
                dataclasses.replace(record, process=mapping[record.inode][0], pid=mapping[record.inode][1])
                if record.inode in mapping else record for record in records
            ]


class ReverseDNS:
    def __init__(self, ttl: float = 300.0, workers: int = 8, timeout: float = 1.0):
        self.ttl = ttl
        self.workers = workers
        self.timeout = timeout
        self._cache: Dict[str, Tuple[float, str]] = {}
        self._lock = threading.Lock()

    def _lookup(self, ip: str) -> str:
        try:
            result = subprocess.run(
                ["getent", "hosts", ip], capture_output=True, text=True,
                timeout=self.timeout, check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                fields = result.stdout.splitlines()[0].split()
                return fields[1] if len(fields) > 1 else ""
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            pass
        return ""

    def resolve(self, records: Sequence[SocketRecord]) -> List[SocketRecord]:
        now = time.monotonic()
        ips = {record.remote_ip for record in records if record.remote_ip not in ("0.0.0.0", "::")}
        names: Dict[str, str] = {}
        with self._lock:
            for ip in ips:
                cached = self._cache.get(ip)
                if cached and now - cached[0] < self.ttl:
                    names[ip] = cached[1]
        missing = sorted(ips.difference(names))
        if missing:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
                futures = {pool.submit(self._lookup, ip): ip for ip in missing}
                pending = set(futures)
                deadline = time.monotonic() + self.timeout
                while pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    completed, pending = concurrent.futures.wait(
                        pending, timeout=remaining, return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    for future in completed:
                        ip = futures[future]
                        try:
                            names[ip] = future.result()
                        except Exception:
                            names[ip] = ""
                for future in pending:
                    future.cancel()
                with self._lock:
                    for ip, name in names.items():
                        self._cache[ip] = (time.monotonic(), name)
                    if len(self._cache) > 10000:
                        self._cache = {k: v for k, v in self._cache.items() if now - v[0] < self.ttl}
        return [dataclasses.replace(record, hostname=names.get(record.remote_ip, "")) for record in records]


class ConnectionTracker:
    def __init__(self, history_limit: int = 24, retention_seconds: float = 300.0, max_tracked: int = 100000):
        self.history_limit = history_limit
        self.retention_seconds = retention_seconds
        self.max_tracked = max_tracked
        self.active: Dict[Tuple[Any, ...], TrackedConnection] = {}
        self.retired: Deque[Tuple[float, TrackedConnection]] = collections.deque()
        self.total_seen = 0
        self.total_disappeared = 0
        self.total_transitions = 0

    def _new(self, record: SocketRecord, snapshot: Snapshot) -> TrackedConnection:
        event = StateEvent(snapshot.timestamp, snapshot.monotonic, None, record.state, "appeared", 0.0)
        tracked = TrackedConnection(
            record=record, first_seen=snapshot.monotonic, last_seen=snapshot.monotonic,
            first_seen_at=snapshot.timestamp, last_seen_at=snapshot.timestamp,
            events=collections.deque([event], maxlen=self.history_limit),
            observed_fin=record.state in FIN_STATES,
            last_state_change=snapshot.monotonic
        )
        self.total_seen += 1
        return tracked

    def update(self, snapshot: Snapshot, allow_disappearance: bool = True) -> CycleResult:
        appeared: List[TrackedConnection] = []
        changed: List[TrackedConnection] = []
        disappeared: List[TrackedConnection] = []
        seen = set()
        for record in snapshot.records:
            key = record.key
            if key in seen:
                continue
            seen.add(key)
            tracked = self.active.get(key)
            if tracked is None:
                tracked = self._new(record, snapshot)
                self.active[key] = tracked
                appeared.append(tracked)
            else:
                if tracked.record.state != record.state:
                    elapsed = max(0.0, snapshot.monotonic - tracked.last_state_change)
                    tracked.events.append(StateEvent(
                        snapshot.timestamp, snapshot.monotonic, tracked.record.state,
                        record.state, "transition", elapsed
                    ))
                    tracked.transitions += 1
                    self.total_transitions += 1
                    tracked.last_state_change = snapshot.monotonic
                    changed.append(tracked)
                tracked.record = record
                tracked.last_seen = snapshot.monotonic
                tracked.last_seen_at = snapshot.timestamp
                tracked.observed_fin |= record.state in FIN_STATES
        if allow_disappearance:
            for key in list(self.active):
                if key in seen:
                    continue
                tracked = self.active.pop(key)
                tracked.disappeared = True
                tracked.closed_at = snapshot.timestamp
                tracked.disappeared_reason = "no longer present in TCP table; cause not directly observable"
                tracked.events.append(StateEvent(
                    snapshot.timestamp, snapshot.monotonic, tracked.record.state,
                    "ABSENT", "disappeared", max(0.0, snapshot.monotonic - tracked.last_state_change)
                ))
                disappeared.append(tracked)
                self.retired.append((snapshot.monotonic, tracked))
                self.total_disappeared += 1
        self._prune(snapshot.monotonic)
        counts = dict(collections.Counter(conn.record.state for conn in self.active.values()))
        return CycleResult(
            snapshot, list(self.active.values()), appeared, changed, disappeared,
            counts, self.total_seen, self.total_disappeared
        )

    def _prune(self, now: float) -> None:
        while self.retired and (now - self.retired[0][0] > self.retention_seconds or len(self.retired) > self.max_tracked):
            self.retired.popleft()
        if len(self.active) > self.max_tracked:
            victims = sorted(self.active.items(), key=lambda pair: pair[1].last_seen)
            for key, _ in victims[:len(self.active) - self.max_tracked]:
                self.active.pop(key, None)

    def recent(self) -> List[TrackedConnection]:
        return [tracked for _, tracked in self.retired]


@dataclasses.dataclass
class Filters:
    state: str = ""
    local: str = ""
    remote: str = ""
    port: int = 0
    process: str = ""
    fin_only: bool = False
    ipv4_only: bool = False
    ipv6_only: bool = False
    uid: Optional[int] = None
    min_age: float = 0.0

    def __post_init__(self) -> None:
        self.local_network = parse_network(self.local) if self.local else None
        self.remote_network = parse_network(self.remote) if self.remote else None
        self.state = self.state.upper()
        if self.state and self.state not in set(STATE_NAMES.values()):
            raise ValueError(f"unknown TCP state: {self.state}")
        if self.port < 0 or self.port > 65535:
            raise ValueError("port must be between 0 and 65535")
        if self.ipv4_only and self.ipv6_only:
            raise ValueError("IPv4-only and IPv6-only cannot both be enabled")

    def matches(self, conn: TrackedConnection, now: float) -> bool:
        record = conn.record
        if self.state and record.state != self.state:
            return False
        if self.fin_only and record.state not in FIN_STATES:
            return False
        if self.ipv4_only and record.family != socket.AF_INET:
            return False
        if self.ipv6_only and record.family != socket.AF_INET6:
            return False
        if self.port and self.port not in (record.local_port, record.remote_port):
            return False
        if self.process and self.process.casefold() not in record.process.casefold():
            return False
        if self.uid is not None and self.uid != record.uid:
            return False
        if conn.age(now) < self.min_age:
            return False
        if self.local_network and ipaddress.ip_address(record.local_ip) not in self.local_network:
            return False
        if self.remote_network and ipaddress.ip_address(record.remote_ip) not in self.remote_network:
            return False
        return True


class Metrics:
    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self.samples: Deque[Tuple[float, int, int, int, int]] = collections.deque()

    def add(self, result: CycleResult) -> Dict[str, Any]:
        now = result.snapshot.monotonic
        self.samples.append((now, len(result.active), len(result.appeared), len(result.changed), len(result.disappeared)))
        while self.samples and now - self.samples[0][0] > self.window_seconds:
            self.samples.popleft()
        counts = [sample[1] for sample in self.samples]
        duration = max(0.001, now - self.samples[0][0]) if self.samples else 0.001
        return {
            "window_seconds": round(duration, 3),
            "sample_count": len(self.samples),
            "active_mean": round(statistics.fmean(counts), 2) if counts else 0,
            "active_peak": max(counts, default=0),
            "appeared": sum(sample[2] for sample in self.samples),
            "transitions": sum(sample[3] for sample in self.samples),
            "disappeared": sum(sample[4] for sample in self.samples),
            "appearance_rate_per_second": round(sum(sample[2] for sample in self.samples) / duration, 3),
            "disappearance_rate_per_second": round(sum(sample[4] for sample in self.samples) / duration, 3)
        }


class Reporter:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.is_tty = sys.stdout.isatty()
        self.color = not args.no_color and self.is_tty and args.format == "table"
        self.header_count = 0
        self.diagnostic_report: Optional[DiagnosticReport] = None

    def _color(self, value: str) -> str:
        if self.color and value in COLORS:
            return COLORS[value] + value + RESET
        return value

    def _rows(self, connections: Sequence[TrackedConnection], now: float) -> Tuple[List[str], List[List[str]]]:
        headers = ["STATE", "LOCAL", "REMOTE", "PROCESS"]
        if self.args.show_durations:
            headers += ["AGE", "STATE AGE"]
        if self.args.show_queue:
            headers += ["TX", "RX"]
        if self.args.show_state_history:
            headers += ["CHANGES"]
        if self.args.resolve:
            headers += ["HOSTNAME"]
        rows: List[List[str]] = []
        for conn in connections:
            record = conn.record
            row = [record.state, record.local, record.remote, record.process + (f" ({record.pid})" if record.pid is not None else "")]
            if self.args.show_durations:
                row += [format_seconds(conn.age(now)), format_seconds(conn.state_age(now))]
            if self.args.show_queue:
                row += [str(record.tx_queue), str(record.rx_queue)]
            if self.args.show_state_history:
                row += [str(conn.transitions)]
            if self.args.resolve:
                row += [record.hostname]
            rows.append(row)
        return headers, rows

    def _table(self, connections: Sequence[TrackedConnection], now: float) -> None:
        headers, rows = self._rows(connections, now)
        widths = [max([len(header)] + [len(row[i]) for row in rows]) for i, header in enumerate(headers)]
        print("  ".join(header.ljust(widths[i]) for i, header in enumerate(headers)))
        print("  ".join("-" * width for width in widths))
        for row in rows:
            parts = []
            for i, value in enumerate(row):
                padded = value.ljust(widths[i])
                parts.append(self._color(value) + " " * (widths[i] - len(value)) if i == 0 else padded)
            print("  ".join(parts))

    def _details(self, connections: Sequence[TrackedConnection], now: float) -> None:
        for conn in connections:
            if conn.record.state not in FIN_STATES and not self.args.show_state_history:
                continue
            print(f"\n{conn.record.local} -> {conn.record.remote}")
            print(f"  State: {conn.record.state}; age: {format_seconds(conn.age(now))}; transitions: {conn.transitions}")
            if conn.record.state == "FIN_WAIT1":
                print("  Interpretation: local endpoint initiated a graceful close")
            elif conn.record.state == "FIN_WAIT2":
                print("  Interpretation: local FIN acknowledged; awaiting peer FIN")
            elif conn.record.state == "CLOSE_WAIT":
                print("  Interpretation: peer FIN received; local application has not closed")
            elif conn.record.state == "LAST_ACK":
                print("  Interpretation: local FIN sent after peer FIN; awaiting ACK")
            elif conn.record.state == "CLOSING":
                print("  Interpretation: simultaneous close in progress")
            elif conn.record.state == "TIME_WAIT":
                print("  Interpretation: connection teardown completed; TIME_WAIT timer active")
            for event in conn.events:
                print(f"  {event.timestamp}: {event.previous or '-'} -> {event.current} ({event.kind}, {format_seconds(event.elapsed)})")

    def emit(self, result: CycleResult, connections: Sequence[TrackedConnection], metrics: Mapping[str, Any], cycle: int) -> None:
        snapshot = result.snapshot
        if self.args.format in ("json", "jsonl"):
            payload = {
                "version": VERSION, "cycle": cycle, "timestamp": snapshot.timestamp,
                "source": "Linux /proc/net TCP socket state snapshots; not packet capture",
                "counts": result.counts, "active_count": len(result.active),
                "filtered_count": len(connections), "appeared_count": len(result.appeared),
                "changed_count": len(result.changed), "disappeared_count": len(result.disappeared),
                "total_tracked": result.total_tracked,
                "total_disappeared": result.total_disappeared,
                "malformed_records": snapshot.malformed, "truncated": snapshot.truncated,
                "errors": snapshot.errors, "metrics": dict(metrics),
                "connections": [conn.as_dict(snapshot.monotonic, self.args.show_state_history or self.args.show_fin_details) for conn in connections]
            }
            if self.diagnostic_report is not None:
                payload["diagnostics"] = self.diagnostic_report.as_dict()
            if self.args.events:
                payload["events"] = {
                    "appeared": [conn.as_dict(snapshot.monotonic) for conn in result.appeared],
                    "changed": [conn.as_dict(snapshot.monotonic, True) for conn in result.changed],
                    "disappeared": [conn.as_dict(snapshot.monotonic, True) for conn in result.disappeared]
                }
            print(json.dumps(payload, indent=2 if self.args.format == "json" else None, sort_keys=True), flush=True)
            return
        if self.args.clear_screen and self.is_tty and self.args.watch > 0:
            print("\033[2J\033[H", end="")
        print(f"FIN Watcher v{VERSION} | {snapshot.timestamp} | cycle {cycle}")
        print("TCP socket-state observation via /proc; no FIN packet capture")
        print(f"Active: {len(result.active)} | Matching: {len(connections)} | New: {len(result.appeared)} | Changed: {len(result.changed)} | Gone: {len(result.disappeared)}")
        print("States: " + (", ".join(f"{state}={count}" for state, count in sorted(result.counts.items())) or "none"))
        if self.args.stats:
            print("Window: " + ", ".join(f"{key}={value}" for key, value in metrics.items()))
        for error in snapshot.errors:
            print(f"Warning: {error}", file=sys.stderr)
        if snapshot.truncated:
            print("Warning: snapshot truncated; disappearance inference suppressed", file=sys.stderr)
        if not self.args.summary:
            self._table(connections, snapshot.monotonic)
            if self.args.show_fin_details or self.args.show_state_history:
                self._details(connections, snapshot.monotonic)
        if self.args.events:
            for conn in result.disappeared:
                print(f"DISAPPEARED {conn.record.local} -> {conn.record.remote} ({conn.record.state}, last observed)")
        print(flush=True)



@dataclasses.dataclass(frozen=True)
class DiagnosticFinding:
    code: str
    severity: str
    title: str
    explanation: str
    count: int
    examples: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "count": self.count,
            "examples": list(self.examples)
        }


@dataclasses.dataclass
class DiagnosticReport:
    timestamp: str
    scope: str
    count: int
    state_distribution: Dict[str, int]
    family_distribution: Dict[str, int]
    process_distribution: Dict[str, int]
    uid_distribution: Dict[str, int]
    local_port_distribution: Dict[str, int]
    remote_port_distribution: Dict[str, int]
    remote_network_distribution: Dict[str, int]
    age_summary: Dict[str, float]
    queue_summary: Dict[str, Any]
    transition_summary: Dict[str, Any]
    lifecycle_summary: Dict[str, Any]
    findings: List[DiagnosticFinding]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "scope": self.scope,
            "connection_count": self.count,
            "states": self.state_distribution,
            "families": self.family_distribution,
            "processes": self.process_distribution,
            "uids": self.uid_distribution,
            "local_ports": self.local_port_distribution,
            "remote_ports": self.remote_port_distribution,
            "remote_networks": self.remote_network_distribution,
            "ages": self.age_summary,
            "queues": self.queue_summary,
            "transitions": self.transition_summary,
            "lifecycle": self.lifecycle_summary,
            "findings": [finding.as_dict() for finding in self.findings]
        }


class DiagnosticAnalyzer:
    def __init__(
        self,
        top: int = 10,
        close_wait_threshold: int = 25,
        time_wait_threshold: int = 500,
        queue_threshold: int = 65536,
        stale_seconds: float = 120.0,
        high_churn: float = 50.0,
        example_limit: int = 5
    ):
        self.top = max(1, top)
        self.close_wait_threshold = max(1, close_wait_threshold)
        self.time_wait_threshold = max(1, time_wait_threshold)
        self.queue_threshold = max(1, queue_threshold)
        self.stale_seconds = max(0.0, stale_seconds)
        self.high_churn = max(0.0, high_churn)
        self.example_limit = max(1, example_limit)

    @staticmethod
    def _top(counter: collections.Counter) -> Dict[str, int]:
        return dict(sorted(counter.items(), key=lambda item: (-item[1], str(item[0]))))

    def _limited(self, counter: collections.Counter) -> Dict[str, int]:
        return dict(list(self._top(counter).items())[:self.top])

    @staticmethod
    def _remote_network(address: str) -> str:
        try:
            ip = ipaddress.ip_address(address)
            if ip.is_loopback:
                return "loopback"
            if ip.is_link_local:
                return "link-local"
            if ip.is_multicast:
                return "multicast"
            prefix = 24 if ip.version == 4 else 64
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            return str(network)
        except ValueError:
            return "unknown"

    @staticmethod
    def _percentile(values: Sequence[float], percentile: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        position = (len(ordered) - 1) * percentile / 100.0
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        weight = position - lower
        return ordered[lower] * (1.0 - weight) + ordered[upper] * weight

    def _distribution(self, values: Sequence[float]) -> Dict[str, float]:
        if not values:
            return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "p90": 0.0, "p99": 0.0}
        return {
            "min": round(min(values), 3),
            "max": round(max(values), 3),
            "mean": round(statistics.fmean(values), 3),
            "median": round(statistics.median(values), 3),
            "p90": round(self._percentile(values, 90.0), 3),
            "p99": round(self._percentile(values, 99.0), 3)
        }

    def _finding(
        self,
        code: str,
        severity: str,
        title: str,
        explanation: str,
        matching: Sequence[TrackedConnection]
    ) -> DiagnosticFinding:
        examples = tuple(
            f"{conn.record.local} -> {conn.record.remote} ({conn.record.process})"
            for conn in matching[:self.example_limit]
        )
        return DiagnosticFinding(code, severity, title, explanation, len(matching), examples)

    def analyze(
        self,
        result: CycleResult,
        connections: Sequence[TrackedConnection],
        metrics: Mapping[str, Any]
    ) -> DiagnosticReport:
        now = result.snapshot.monotonic
        states = collections.Counter()
        families = collections.Counter()
        processes = collections.Counter()
        uids = collections.Counter()
        local_ports = collections.Counter()
        remote_ports = collections.Counter()
        remote_networks = collections.Counter()
        ages: List[float] = []
        state_ages: List[float] = []
        tx_values: List[float] = []
        rx_values: List[float] = []
        transition_values: List[float] = []
        fin_seen = 0
        with_pid = 0
        retransmit_count = 0
        total_retransmits = 0
        zero_inode = 0
        for conn in connections:
            record = conn.record
            states[record.state] += 1
            families["IPv6" if record.family == socket.AF_INET6 else "IPv4"] += 1
            processes[record.process] += 1
            uids[str(record.uid)] += 1
            local_ports[str(record.local_port)] += 1
            remote_ports[str(record.remote_port)] += 1
            remote_networks[self._remote_network(record.remote_ip)] += 1
            ages.append(conn.age(now))
            state_ages.append(conn.state_age(now))
            tx_values.append(float(record.tx_queue))
            rx_values.append(float(record.rx_queue))
            transition_values.append(float(conn.transitions))
            fin_seen += int(conn.observed_fin)
            with_pid += int(record.pid is not None)
            zero_inode += int(record.inode == 0)
            retransmit_count += int(record.retransmits > 0)
            total_retransmits += record.retransmits
        close_wait = [c for c in connections if c.record.state == "CLOSE_WAIT"]
        time_wait = [c for c in connections if c.record.state == "TIME_WAIT"]
        fin_wait2 = [c for c in connections if c.record.state == "FIN_WAIT2"]
        last_ack = [c for c in connections if c.record.state == "LAST_ACK"]
        queued_tx = [c for c in connections if c.record.tx_queue >= self.queue_threshold]
        queued_rx = [c for c in connections if c.record.rx_queue >= self.queue_threshold]
        stale_close = [c for c in close_wait if c.state_age(now) >= self.stale_seconds]
        stale_fin = [c for c in fin_wait2 if c.state_age(now) >= self.stale_seconds]
        stale_ack = [c for c in last_ack if c.state_age(now) >= self.stale_seconds]
        retransmitting = [c for c in connections if c.record.retransmits > 0]
        findings: List[DiagnosticFinding] = []
        if len(close_wait) >= self.close_wait_threshold:
            findings.append(self._finding(
                "CLOSE_WAIT_VOLUME", "warning", "Elevated CLOSE_WAIT count",
                "Remote peers have closed, but local applications may not have closed their sockets.",
                close_wait
            ))
        if stale_close:
            findings.append(self._finding(
                "CLOSE_WAIT_AGE", "warning", "Long-observed CLOSE_WAIT sockets",
                "Observed state age is based on polling and is not the exact kernel transition time.",
                stale_close
            ))
        if len(time_wait) >= self.time_wait_threshold:
            findings.append(self._finding(
                "TIME_WAIT_VOLUME", "info", "High TIME_WAIT population",
                "TIME_WAIT is normal during TCP teardown; compare counts with workload and churn.",
                time_wait
            ))
        if stale_fin:
            findings.append(self._finding(
                "FIN_WAIT2_AGE", "warning", "Long-observed FIN_WAIT2 sockets",
                "The local FIN has been acknowledged; the peer's FIN may still be pending.",
                stale_fin
            ))
        if stale_ack:
            findings.append(self._finding(
                "LAST_ACK_AGE", "warning", "Long-observed LAST_ACK sockets",
                "The local side is waiting for acknowledgment of its FIN.",
                stale_ack
            ))
        if queued_tx:
            findings.append(self._finding(
                "TX_QUEUE", "warning", "Large transmit queues",
                "Queued transmit bytes may indicate backpressure or a slow peer.",
                queued_tx
            ))
        if queued_rx:
            findings.append(self._finding(
                "RX_QUEUE", "warning", "Large receive queues",
                "Queued receive bytes may indicate an application is not draining data promptly.",
                queued_rx
            ))
        if retransmitting:
            findings.append(self._finding(
                "RETRANSMITS", "info", "Sockets reporting retransmission counters",
                "This is a snapshot indicator, not a measured packet retransmission rate.",
                retransmitting
            ))
        appearance_rate = float(metrics.get("appearance_rate_per_second", 0.0))
        if appearance_rate >= self.high_churn:
            findings.append(DiagnosticFinding(
                "HIGH_CHURN", "info", "High observed connection churn",
                "New socket observations per second exceed the configured threshold.",
                int(metrics.get("appeared", 0)), ()
            ))
        if result.snapshot.truncated:
            findings.append(DiagnosticFinding(
                "TRUNCATED", "warning", "Incomplete socket snapshot",
                "Some connections were omitted; counts and trends may be underestimates.",
                len(connections), ()
            ))
        if result.snapshot.errors:
            findings.append(DiagnosticFinding(
                "READ_ERRORS", "warning", "Socket table read errors",
                "One or more TCP tables could not be read completely.",
                len(result.snapshot.errors), tuple(result.snapshot.errors[:self.example_limit])
            ))
        findings.sort(key=lambda item: (0 if item.severity == "warning" else 1, -item.count, item.code))
        return DiagnosticReport(
            timestamp=result.snapshot.timestamp,
            scope="filtered active TCP sockets",
            count=len(connections),
            state_distribution=self._top(states),
            family_distribution=self._top(families),
            process_distribution=self._limited(processes),
            uid_distribution=self._limited(uids),
            local_port_distribution=self._limited(local_ports),
            remote_port_distribution=self._limited(remote_ports),
            remote_network_distribution=self._limited(remote_networks),
            age_summary={
                **self._distribution(ages),
                "state_age_mean": round(statistics.fmean(state_ages), 3) if state_ages else 0.0,
                "state_age_p90": round(self._percentile(state_ages, 90.0), 3),
            },
            queue_summary={
                "tx": self._distribution(tx_values),
                "rx": self._distribution(rx_values),
                "total_tx_bytes": sum(int(v) for v in tx_values),
                "total_rx_bytes": sum(int(v) for v in rx_values),
                "large_tx": len(queued_tx),
                "large_rx": len(queued_rx),
            },
            transition_summary={
                "per_connection": self._distribution(transition_values),
                "observed_fin_lifecycle": fin_seen,
                "observed_retransmitting": retransmit_count,
                "retransmit_counter_total": total_retransmits,
            },
            lifecycle_summary={
                "appeared_this_cycle": len(result.appeared),
                "changed_this_cycle": len(result.changed),
                "disappeared_this_cycle": len(result.disappeared),
                "total_tracked": result.total_tracked,
                "total_disappeared": result.total_disappeared,
                "with_pid": with_pid,
                "without_inode": zero_inode,
                "appearance_rate_per_second": appearance_rate,
                "disappearance_rate_per_second": metrics.get("disappearance_rate_per_second", 0.0),
            },
            findings=findings
        )


class DiagnosticFormatter:
    @staticmethod
    def _group(title: str, values: Mapping[str, Any]) -> List[str]:
        lines = [title + ":"]
        if not values:
            lines.append("  none")
        for key, value in values.items():
            lines.append(f"  {key:<28} {value}")
        return lines

    @classmethod
    def render(cls, report: DiagnosticReport, show_examples: bool = False) -> str:
        lines = [
            "TCP DIAGNOSTICS",
            f"  Scope: {report.scope}",
            f"  Connections: {report.count}",
            "  Findings are observational heuristics, not proof of a network fault.",
            ""
        ]
        groups = [
            ("States", report.state_distribution),
            ("IP families", report.family_distribution),
            ("Top processes", report.process_distribution),
            ("Top local ports", report.local_port_distribution),
            ("Top remote ports", report.remote_port_distribution),
            ("Top remote networks", report.remote_network_distribution),
            ("Connection ages (seconds)", report.age_summary),
            ("Queue totals", {
                "tx_bytes": report.queue_summary["total_tx_bytes"],
                "rx_bytes": report.queue_summary["total_rx_bytes"],
                "large_tx": report.queue_summary["large_tx"],
                "large_rx": report.queue_summary["large_rx"]
            }),
            ("Lifecycle", report.lifecycle_summary)
        ]
        for title, values in groups:
            lines.extend(cls._group(title, values))
            lines.append("")
        lines.append("Findings:")
        if not report.findings:
            lines.append("  No configured diagnostic thresholds exceeded")
        for finding in report.findings:
            lines.append(f"  [{finding.severity.upper()}] {finding.code}: {finding.title} ({finding.count})")
            lines.append(f"    {finding.explanation}")
            if show_examples:
                for example in finding.examples:
                    lines.append(f"    {example}")
        return "\n".join(lines)


class DiagnosticArchive:
    def __init__(self, path: str, max_bytes: int = 10485760):
        self.path = pathlib.Path(path).expanduser()
        self.max_bytes = max_bytes

    def append(self, report: DiagnosticReport) -> None:
        if not self.path.parent.exists():
            raise OSError(f"diagnostic archive directory does not exist: {self.path.parent}")
        encoded = json.dumps(report.as_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        if len(encoded.encode("utf-8")) > self.max_bytes:
            raise ValueError("diagnostic record exceeds archive size limit")
        if self.path.exists() and self.path.stat().st_size + len(encoded.encode("utf-8")) > self.max_bytes:
            rotated = self.path.with_name(self.path.name + ".1")
            self.path.replace(rotated)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()


def sort_connections(connections: Iterable[TrackedConnection], field: str, now: float) -> List[TrackedConnection]:
    getters = {
        "state": lambda c: (c.record.state, c.record.local_ip, c.record.local_port),
        "local_ip": lambda c: (ipaddress.ip_address(c.record.local_ip).version, int(ipaddress.ip_address(c.record.local_ip)), c.record.local_port),
        "remote_ip": lambda c: (ipaddress.ip_address(c.record.remote_ip).version, int(ipaddress.ip_address(c.record.remote_ip)), c.record.remote_port),
        "port": lambda c: (c.record.local_port, c.record.remote_port),
        "process": lambda c: (c.record.process.casefold(), c.record.pid or 0),
        "duration": lambda c: -c.age(now),
        "state_age": lambda c: -c.state_age(now),
        "tx_queue": lambda c: -c.record.tx_queue,
        "rx_queue": lambda c: -c.record.rx_queue,
        "changes": lambda c: -c.transitions
    }
    return sorted(connections, key=getters[field])


def positive_float(value: str) -> float:
    parsed = float(value)
    if not 0 < parsed < float("inf"):
        raise argparse.ArgumentTypeError("must be finite and positive")
    return parsed


def nonnegative_float(value: str) -> float:
    parsed = float(value)
    if not 0 <= parsed < float("inf"):
        raise argparse.ArgumentTypeError("must be finite and nonnegative")
    return parsed


def bounded_integer(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 1000000:
        raise argparse.ArgumentTypeError("must be between 1 and 1000000")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Linux TCP FIN-state and socket lifecycle observer")
    parser.add_argument("--version", action="version", version=f"FIN Watcher {VERSION}")
    parser.add_argument("--tcp-file", default=TCP4)
    parser.add_argument("--tcp6-file", default=TCP6)
    parser.add_argument("--watch", type=nonnegative_float, default=2.0, metavar="SECONDS")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--cycles", type=bounded_integer, default=0)
    parser.add_argument("--state", default="")
    parser.add_argument("--local-ip", default="")
    parser.add_argument("--remote-ip", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--process", default="")
    parser.add_argument("--uid", type=int)
    parser.add_argument("--ipv4-only", action="store_true")
    parser.add_argument("--ipv6-only", action="store_true")
    parser.add_argument("--watch-fin", action="store_true")
    parser.add_argument("--min-age", type=nonnegative_float, default=0.0)
    parser.add_argument("--sort", choices=["state", "local_ip", "remote_ip", "port", "process", "duration", "state_age", "tx_queue", "rx_queue", "changes"], default="state")
    parser.add_argument("--format", choices=["table", "json", "jsonl"], default="table")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-clear-screen", action="store_true")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("--events", action="store_true")
    parser.add_argument("--show-durations", action="store_true")
    parser.add_argument("--show-fin-details", action="store_true")
    parser.add_argument("--show-queue", action="store_true")
    parser.add_argument("--show-state-history", action="store_true")
    parser.add_argument("--resolve", action="store_true")
    parser.add_argument("--resolve-timeout", type=positive_float, default=1.0)
    parser.add_argument("--max-dns", type=bounded_integer, default=8)
    parser.add_argument("--dns-ttl", type=positive_float, default=300.0)
    parser.add_argument("--max-process-age", type=nonnegative_float, default=5.0)
    parser.add_argument("--no-process-scan", action="store_true")
    parser.add_argument("--max-connections", type=bounded_integer, default=100000)
    parser.add_argument("--max-tracked", type=bounded_integer, default=100000)
    parser.add_argument("--history-limit", type=bounded_integer, default=24)
    parser.add_argument("--retention", type=nonnegative_float, default=300.0)
    parser.add_argument("--metrics-window", type=positive_float, default=60.0)
    parser.add_argument("--diagnostics", action="store_true")
    parser.add_argument("--diagnostic-examples", action="store_true")
    parser.add_argument("--diagnostic-top", type=bounded_integer, default=10)
    parser.add_argument("--close-wait-threshold", type=bounded_integer, default=25)
    parser.add_argument("--time-wait-threshold", type=bounded_integer, default=500)
    parser.add_argument("--queue-threshold", type=bounded_integer, default=65536)
    parser.add_argument("--stale-threshold", type=nonnegative_float, default=120.0)
    parser.add_argument("--churn-threshold", type=nonnegative_float, default=50.0)
    parser.add_argument("--diagnostic-archive", default="")
    parser.add_argument("--archive-max-bytes", type=bounded_integer, default=10485760)
    parser.add_argument("--config", metavar="FILE")
    return parser


def load_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = build_parser()
    initial, _ = parser.parse_known_args(argv)
    if initial.config:
        with open(initial.config, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        if not isinstance(config, dict):
            parser.error("configuration must be a JSON object")
        known = {action.dest: action for action in parser._actions}
        defaults = {}
        for name, value in config.items():
            dest = name.replace("-", "_")
            if dest not in known or dest in ("help", "version", "config"):
                parser.error(f"unknown configuration key: {name}")
            action = known[dest]
            if isinstance(action, argparse._StoreTrueAction):
                if not isinstance(value, bool):
                    parser.error(f"configuration key {name} requires boolean")
            elif action.type is not None:
                try:
                    value = action.type(str(value))
                except (ValueError, TypeError, argparse.ArgumentTypeError) as exc:
                    parser.error(f"invalid configuration value for {name}: {exc}")
            if action.choices and value not in action.choices:
                parser.error(f"invalid choice for {name}: {value}")
            defaults[dest] = value
        parser.set_defaults(**defaults)
    args = parser.parse_args(argv)
    if args.once:
        args.watch = 0.0
    args.clear_screen = not args.no_clear_screen
    if args.watch and args.watch < 0.1:
        parser.error("watch interval must be at least 0.1 seconds")
    if args.max_dns > 128:
        parser.error("max-dns must be at most 128")
    if args.uid is not None and args.uid < 0:
        parser.error("uid must be nonnegative")
    if args.format != "table":
        args.clear_screen = False
    return args


def run(args: argparse.Namespace) -> int:
    if not sys.platform.startswith("linux"):
        print("FIN Watcher requires Linux", file=sys.stderr)
        return 2
    filters = Filters(
        state=args.state, local=args.local_ip, remote=args.remote_ip,
        port=args.port, process=args.process, fin_only=args.watch_fin,
        ipv4_only=args.ipv4_only, ipv6_only=args.ipv6_only,
        uid=args.uid, min_age=args.min_age
    )
    reader = ProcReader(args.tcp_file, args.tcp6_file, args.max_connections)
    processes = ProcessResolver(args.max_process_age)
    dns = ReverseDNS(args.dns_ttl, args.max_dns, args.resolve_timeout)
    tracker = ConnectionTracker(args.history_limit, args.retention, args.max_tracked)
    metrics = Metrics(args.metrics_window)
    reporter = Reporter(args)
    analyzer = DiagnosticAnalyzer(
        top=args.diagnostic_top,
        close_wait_threshold=args.close_wait_threshold,
        time_wait_threshold=args.time_wait_threshold,
        queue_threshold=args.queue_threshold,
        stale_seconds=args.stale_threshold,
        high_churn=args.churn_threshold
    )
    archive = DiagnosticArchive(args.diagnostic_archive, args.archive_max_bytes) if args.diagnostic_archive else None
    stop = threading.Event()
    original_handlers = {}

    def on_signal(signum: int, frame: Any) -> None:
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            original_handlers[sig] = signal.signal(sig, on_signal)
        except ValueError:
            pass
    cycle = 0
    try:
        while not stop.is_set():
            started = time.monotonic()
            snapshot = reader.read()
            if not snapshot.records and any("cannot read" in error or "missing required" in error for error in snapshot.errors):
                for error in snapshot.errors:
                    print(f"Error: {error}", file=sys.stderr)
                return 1
            if not args.no_process_scan:
                snapshot.records = processes.resolve(snapshot.records, snapshot.monotonic)
            if args.resolve:
                snapshot.records = dns.resolve(snapshot.records)
            result = tracker.update(snapshot, allow_disappearance=not snapshot.truncated and not snapshot.errors)
            connections = [conn for conn in result.active if filters.matches(conn, snapshot.monotonic)]
            connections = sort_connections(connections, args.sort, snapshot.monotonic)
            metric_values = metrics.add(result)
            cycle += 1
            if args.diagnostics or archive is not None:
                diagnostic_report = analyzer.analyze(result, connections, metric_values)
                reporter.diagnostic_report = diagnostic_report if args.diagnostics else None
                if archive is not None:
                    archive.append(diagnostic_report)
            reporter.emit(result, connections, metric_values, cycle)
            if args.watch <= 0 or (args.cycles and cycle >= args.cycles):
                break
            stop.wait(max(0.0, args.watch - (time.monotonic() - started)))
    finally:
        for sig, handler in original_handlers.items():
            signal.signal(sig, handler)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        return run(load_arguments(argv))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FIN Watcher error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
