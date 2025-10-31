
"""Stability monitoring utilities for long-running deployments.

This module provides a reusable monitor that periodically checks resource
consumption, thread health and storage usage. The goal is to detect issues
before they accumulate into long-term failures when the application runs for
extended periods without a restart.
"""
from __future__ import annotations

import logging
import os
import shutil
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from functools import wraps
from typing import Callable, Dict, Iterable, Optional

import psutil

ThreadSupplier = Callable[[], Optional[threading.Thread]]
RestartCallback = Callable[[], None]
PeriodicCallable = Callable[[], None]
CleanupCallback = Callable[[], None]


@dataclass
class _ThreadWatch:
    name: str
    supplier: ThreadSupplier
    restart: Optional[RestartCallback] = None
    grace_period: float = 0.0
    _last_failure_log: float = field(default=0.0, init=False)


@dataclass
class _DirectoryQuota:
    path: str
    max_bytes: int
    min_free_bytes: Optional[int] = None


@dataclass
class _PeriodicTask:
    name: str
    interval: float
    func: PeriodicCallable
    next_run: float = field(default_factory=lambda: time.monotonic())


class StabilityMonitor:
    """Background monitor that attempts to prevent long-term degradation."""

    def __init__(
        self,
        *,
        check_interval: float = 60.0,
        memory_warning_mb: int = 800,
        memory_critical_mb: int = 1024,
        log_file_path: Optional[str] = None,
    ) -> None:
        self._check_interval = max(10.0, float(check_interval))
        self._memory_warning = max(0, memory_warning_mb) * 1024 * 1024
        critical_bytes = memory_critical_mb * 1024 * 1024
        self._memory_critical = max(self._memory_warning, critical_bytes)

        self._process = psutil.Process(os.getpid())
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._thread = threading.Thread(
            target=self._run,
            name="StabilityMonitor",
            daemon=True,
        )

        self._thread_watches: Dict[str, _ThreadWatch] = {}
        self._directory_quotas: Dict[str, _DirectoryQuota] = {}
        self._periodic_tasks: Dict[str, _PeriodicTask] = {}
        self._memory_cleanup_callbacks: list[CleanupCallback] = []
        self._last_cleanup_run: float = 0.0

        self._log_file_path = log_file_path
        self._last_daily_report_date: Optional[date] = None
        self._last_weekly_report_date: Optional[date] = None
        self._call_counters: Dict[str, Counter[str]] = {
            "daily": Counter(),
            "weekly": Counter(),
        }
        self._tracked_method_names: list[str] = []
        self._role: str = "unknown"

        self._request_statistics_callback: Optional[Callable[[str], None]] = None
        self._get_client_names_callback: Optional[Callable[[], Iterable[str]]] = None
        self._statistics_wait_seconds: float = 3.0
        self._remote_stats_lock = threading.RLock()
        self._remote_statistics_latest: Dict[str, Dict[str, dict]] = defaultdict(dict)
        self._pending_statistics: Dict[str, dict] = {}
        self._pending_period: Optional[str] = None
        self._statistics_event = threading.Event()

    # ------------------------------------------------------------------
    # Life-cycle management
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start the monitor thread if it is not already running."""
        if self._thread.is_alive():
            return
        logging.debug("Starting stability monitor background thread")
        self._thread.start()

    def stop(self) -> None:
        """Stop the monitor thread and wait for it to exit."""
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self._check_interval)

    # ------------------------------------------------------------------
    # Registration helpers
    # ------------------------------------------------------------------
    def register_thread(
        self,
        name: str,
        supplier: ThreadSupplier,
        *,
        restart: Optional[RestartCallback] = None,
        grace_period: float = 5.0,
    ) -> None:
        """Register a thread supplier for liveness monitoring."""
        with self._lock:
            self._thread_watches[name] = _ThreadWatch(
                name=name,
                supplier=supplier,
                restart=restart,
                grace_period=max(0.0, float(grace_period)),
            )

    def unregister_thread(self, name: str) -> None:
        with self._lock:
            self._thread_watches.pop(name, None)

    def add_directory_quota(
        self,
        path: str,
        *,
        max_mb: int,
        min_free_mb: Optional[int] = None,
    ) -> None:
        """Ensure the directory stays below the requested quota."""
        absolute = os.path.abspath(path)
        with self._lock:
            self._directory_quotas[absolute] = _DirectoryQuota(
                path=absolute,
                max_bytes=max(0, max_mb) * 1024 * 1024,
                min_free_bytes=(
                    None if min_free_mb is None else max(0, min_free_mb) * 1024 * 1024
                ),
            )

    def remove_directory_quota(self, path: str) -> None:
        absolute = os.path.abspath(path)
        with self._lock:
            self._directory_quotas.pop(absolute, None)

    def add_periodic_task(self, name: str, interval_seconds: float, func: PeriodicCallable) -> None:
        with self._lock:
            self._periodic_tasks[name] = _PeriodicTask(
                name=name,
                interval=max(10.0, float(interval_seconds)),
                func=func,
            )

    def remove_periodic_task(self, name: str) -> None:
        with self._lock:
            self._periodic_tasks.pop(name, None)

    def register_memory_cleanup(self, callback: CleanupCallback) -> None:
        with self._lock:
            self._memory_cleanup_callbacks.append(callback)

    def unregister_memory_cleanup(self, callback: CleanupCallback) -> None:
        with self._lock:
            try:
                self._memory_cleanup_callbacks.remove(callback)
            except ValueError:
                pass

    def update_log_file_path(self, path: Optional[str]) -> None:
        with self._lock:
            self._log_file_path = path

    def configure_role(
        self,
        *,
        role: str,
        log_file_path: Optional[str] = None,
        request_statistics_callback: Optional[Callable[[str], None]] = None,
        get_client_names_callback: Optional[Callable[[], Iterable[str]]] = None,
    ) -> None:
        with self._lock:
            self._role = role
            if log_file_path is not None:
                self._log_file_path = log_file_path
        with self._remote_stats_lock:
            if request_statistics_callback is not None:
                self._request_statistics_callback = request_statistics_callback
            if get_client_names_callback is not None:
                self._get_client_names_callback = get_client_names_callback

    def track_method_call(self, method_name: str) -> Callable[[Callable], Callable]:
        with self._lock:
            if method_name not in self._tracked_method_names:
                self._tracked_method_names.append(method_name)
            for counter in self._call_counters.values():
                counter.setdefault(method_name, 0)

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                with self._lock:
                    for counter in self._call_counters.values():
                        counter[method_name] += 1
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def _consume_call_counts(self, period: str) -> tuple[list[str], Dict[str, int]]:
        with self._lock:
            method_names = list(self._tracked_method_names)
            counter = self._call_counters.get(period)
            if counter is None:
                return method_names, {name: 0 for name in method_names}
            snapshot = {name: counter.get(name, 0) for name in method_names}
            counter.clear()
        return method_names, snapshot

    def _check_and_generate_reports(self) -> None:
        with self._lock:
            if self._role != "ado":
                return
            log_file_path = self._log_file_path
            last_daily = self._last_daily_report_date
            last_weekly = self._last_weekly_report_date

        if not log_file_path:
            return

        today = date.today()
        try:
            if last_daily != today:
                self._generate_report("daily", log_file_path)
                with self._lock:
                    self._last_daily_report_date = today

            if last_weekly is None or (today - last_weekly).days >= 7:
                self._generate_report("weekly", log_file_path)
                with self._lock:
                    self._last_weekly_report_date = today
        except Exception:
            logging.exception("Failed to generate stability monitor report")

    def _generate_report(self, period: str, log_file_path: str) -> None:
        period_config = {
            "daily": {
                "title": "Napi Működési Jelentés",
                "timeframe": "Az elmúlt 24 óra",
                "delta": timedelta(days=1),
                "filename": "daily_report.md",
            },
            "weekly": {
                "title": "Heti Működési Jelentés",
                "timeframe": "Az elmúlt 7 nap",
                "delta": timedelta(days=7),
                "filename": "weekly_report.md",
            },
        }

        if period not in period_config:
            raise ValueError(f"Unsupported report period: {period}")

        config = period_config[period]
        now = datetime.now()
        start_time = now - config["delta"]

        remote_statistics = self._request_remote_statistics(period)
        method_names, call_counts = self._consume_call_counts(period)

        per_source_stats, overall_messages = self._analyse_log_file(log_file_path, start_time)

        controller_label = "Központi vezérlő"
        per_source_stats.setdefault(controller_label, {"warnings": 0, "errors": 0, "messages": Counter()})
        for client_name in remote_statistics.keys():
            per_source_stats.setdefault(client_name, {"warnings": 0, "errors": 0, "messages": Counter()})

        report_lines = [
            f"# KVM Alkalmazás - {config['title']}",
            "",
            f"**Jelentés időpontja:** {now.strftime('%Y-%m-%d %H:%M')}",
            "",
            f"**Vizsgált időszak:** {config['timeframe']}",
            "",
            "---",
            "",
            "## Összesített stabilitás",
            "",
            "| Forrás | Figyelmeztetés (WARNING) | Hiba (ERROR/CRITICAL) |",
            "|--------|--------------------------|-----------------------|",
        ]

        for source_name in sorted(per_source_stats.keys()):
            stats = per_source_stats[source_name]
            report_lines.append(
                f"| {source_name} | {stats['warnings']:,} | {stats['errors']:,} |"
            )

        report_lines.extend([
            "",
            "**Leggyakoribb hibák/figyelmeztetések (összesített):**",
        ])
        common_messages = overall_messages.most_common(5)
        if common_messages:
            for idx, (message, count) in enumerate(common_messages, start=1):
                report_lines.append(f"{idx}. `{message}` ({count} alkalommal)")
        else:
            report_lines.append("Nincs rögzített hiba vagy figyelmeztetés az időszakban.")

        def _append_section(
            title: str,
            log_stats: dict,
            stats_messages: Counter[str],
            methods: list[str],
            counters: Dict[str, int],
        ) -> None:
            report_lines.extend([
                "",
                "---",
                "",
                f"## {title}",
                "",
                "### Hiba- és figyelmeztetés statisztika",
                "",
                f"- Figyelmeztetések (WARNING): {log_stats.get('warnings', 0):,}",
                f"- Hibák (ERROR/CRITICAL): {log_stats.get('errors', 0):,}",
                "",
                "### Gyakori üzenetek",
            ])
            common_local = stats_messages.most_common(3)
            if common_local:
                for idx, (message, count) in enumerate(common_local, start=1):
                    report_lines.append(f"{idx}. `{message}` ({count} alkalommal)")
            else:
                report_lines.append("Nincs rögzített figyelmeztetés vagy hiba ebben az időszakban.")

            report_lines.extend([
                "",
                "### Fő funkciók használata",
                "",
                "| Funkció Neve              | Hívások Száma |",
                "|---------------------------|---------------|",
            ])
            if not methods:
                report_lines.append("| *(nincs monitorozott függvény)* | 0 |")
            else:
                for name in methods:
                    report_lines.append(f"| `{name}` | {counters.get(name, 0):,} |")

        _append_section(
            "Központi vezérlő",
            per_source_stats[controller_label],
            per_source_stats[controller_label]["messages"],
            method_names,
            call_counts,
        )

        for client_name in sorted(k for k in per_source_stats.keys() if k != controller_label):
            client_log_stats = per_source_stats[client_name]
            client_methods = remote_statistics.get(client_name, {}).get("methods", [])
            client_counters = remote_statistics.get(client_name, {}).get("counters", {})
            _append_section(
                client_name,
                client_log_stats,
                client_log_stats["messages"],
                client_methods,
                client_counters,
            )

        report_lines.extend([
            "",
            "---",
            "*Ez egy automatikusan generált jelentés.*",
            "",
        ])

        report_path = os.path.join(os.path.dirname(log_file_path), config["filename"])
        try:
            with open(report_path, "w", encoding="utf-8") as report_file:
                report_file.write("\n".join(report_lines))
            logging.info("Stability report generated: %s", report_path)
        except Exception:
            logging.exception("Failed to write %s report", period)

    def _analyse_log_file(
        self, log_file_path: str, start_time: datetime
    ) -> tuple[Dict[str, dict], Counter[str]]:
        per_source: Dict[str, dict] = defaultdict(
            lambda: {"warnings": 0, "errors": 0, "messages": Counter()}
        )
        overall_messages: Counter[str] = Counter()

        if not os.path.exists(log_file_path):
            return per_source, overall_messages

        try:
            with open(log_file_path, "r", encoding="utf-8") as log_file:
                for raw_line in log_file:
                    line = raw_line.strip()
                    if not line:
                        continue
                    parts = line.split(" - ", 4)
                    if len(parts) < 4:
                        continue
                    timestamp_str = parts[0]
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
                    except ValueError:
                        continue
                    if timestamp < start_time:
                        continue

                    if len(parts) == 5 and parts[1].startswith("[") and parts[1].endswith("]"):
                        source_name = parts[1][1:-1]
                        level = parts[2]
                        message = parts[4]
                    else:
                        source_name = "Központi vezérlő"
                        level = parts[1]
                        message = parts[3] if len(parts) > 3 else ""

                    level = level.upper()
                    if level == "WARNING":
                        per_source[source_name]["warnings"] += 1
                        per_source[source_name]["messages"][message] += 1
                        overall_messages[message] += 1
                    elif level in {"ERROR", "CRITICAL"}:
                        per_source[source_name]["errors"] += 1
                        per_source[source_name]["messages"][message] += 1
                        overall_messages[message] += 1
        except Exception:
            logging.exception("Failed to analyse log file for aggregated report")

        return per_source, overall_messages

    def _request_remote_statistics(self, period: str) -> Dict[str, dict]:
        callback = self._request_statistics_callback
        if callback is None:
            with self._remote_stats_lock:
                return dict(self._remote_statistics_latest.get(period, {}))

        expected = None
        if self._get_client_names_callback:
            try:
                names = list(self._get_client_names_callback())
                expected = len(names)
            except Exception:
                logging.exception("Failed to enumerate clients for statistics request")

        with self._remote_stats_lock:
            self._pending_period = period
            self._pending_statistics.clear()
            self._statistics_event.clear()

        try:
            callback(period)
        except Exception:
            logging.exception("Failed to request client statistics for period %s", period)
            with self._remote_stats_lock:
                self._pending_period = None
                return dict(self._remote_statistics_latest.get(period, {}))

        deadline = time.monotonic() + self._statistics_wait_seconds
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            triggered = self._statistics_event.wait(timeout=min(0.5, remaining))
            if triggered:
                self._statistics_event.clear()
            if expected is not None:
                with self._remote_stats_lock:
                    if len(self._pending_statistics) >= expected:
                        break

        with self._remote_stats_lock:
            if self._pending_statistics:
                latest = self._remote_statistics_latest.setdefault(period, {})
                latest.update(self._pending_statistics)
                self._pending_statistics.clear()
            snapshot = dict(self._remote_statistics_latest.get(period, {}))
            self._pending_period = None
        return snapshot

    def record_remote_statistics(
        self,
        source: str,
        period: str,
        methods: Iterable[str],
        counters: Dict[str, int],
    ) -> None:
        payload = {
            "methods": list(methods),
            "counters": {str(k): int(v) for k, v in counters.items()},
            "received_at": datetime.now(),
        }
        with self._remote_stats_lock:
            latest = self._remote_statistics_latest.setdefault(period, {})
            latest[source] = payload
            if self._pending_period == period:
                self._pending_statistics[source] = payload
            self._statistics_event.set()

    def generate_statistics_snapshot(self, period: str) -> Dict[str, dict]:
        methods, counters = self._consume_call_counts(period)
        return {"methods": methods, "counters": counters}
    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _run(self) -> None:
        logging.info("Stability monitor thread running")
        while not self._stop_event.is_set():
            start = time.monotonic()
            try:
                if self._role == "ado":
                    self._check_and_generate_reports()
                self._check_memory()
                self._check_threads()
                self._check_directories()
                self._run_periodic_tasks()
            except Exception:
                logging.exception("Unexpected error while running stability checks")
            elapsed = time.monotonic() - start
            sleep_for = max(1.0, self._check_interval - elapsed)
            self._stop_event.wait(timeout=sleep_for)
        logging.info("Stability monitor thread stopped")

    def _check_memory(self) -> None:
        try:
            rss = self._process.memory_info().rss
        except Exception as exc:
            logging.debug("Could not query RSS memory usage: %s", exc)
            return

        if rss >= self._memory_warning:
            logging.warning(
                "Process memory usage is high: %.1f MB (warning threshold %.1f MB)",
                rss / (1024 * 1024),
                self._memory_warning / (1024 * 1024),
            )

        now = time.monotonic()
        if rss >= self._memory_critical and now - self._last_cleanup_run > self._check_interval:
            self._last_cleanup_run = now
            with self._lock:
                callbacks = tuple(self._memory_cleanup_callbacks)
            if not callbacks:
                logging.critical(
                    "Memory usage exceeded critical threshold (%.1f MB) but no cleanup callbacks are registered",
                    rss / (1024 * 1024),
                )
                return
            logging.critical(
                "Memory usage exceeded critical threshold (%.1f MB); running cleanup callbacks",
                rss / (1024 * 1024),
            )
            for callback in callbacks:
                try:
                    callback()
                except Exception:
                    logging.exception("Memory cleanup callback %r failed", callback)

    def _check_threads(self) -> None:
        with self._lock:
            watches = list(self._thread_watches.values())
        now = time.monotonic()
        for watch in watches:
            try:
                thread = watch.supplier()
            except Exception:
                logging.exception("Thread supplier %s raised an exception", watch.name)
                continue
            if thread is None or thread.is_alive():
                continue
            if now - watch._last_failure_log < max(self._check_interval, watch.grace_period):
                continue
            watch._last_failure_log = now
            logging.error("Background thread %s is not alive", watch.name)
            if watch.restart:
                try:
                    watch.restart()
                except Exception:
                    logging.exception("Failed to restart thread %s", watch.name)

    def _check_directories(self) -> None:
        with self._lock:
            quotas = list(self._directory_quotas.values())
        for quota in quotas:
            path = quota.path
            if not os.path.isdir(path):
                continue
            try:
                total_size, files = self._collect_directory_usage(path)
            except Exception:
                logging.exception("Failed to collect directory usage for %s", path)
                continue

            disk_ok = True
            if quota.min_free_bytes:
                try:
                    free_bytes = shutil.disk_usage(path).free
                    disk_ok = free_bytes >= quota.min_free_bytes
                except Exception:
                    disk_ok = True
            exceeds_quota = total_size > quota.max_bytes if quota.max_bytes else False
            if not exceeds_quota and disk_ok:
                continue

            logging.warning(
                "Directory %s is exceeding limits (size %.1f MB, quota %.1f MB, disk ok=%s). Initiating cleanup.",
                path,
                total_size / (1024 * 1024),
                quota.max_bytes / (1024 * 1024),
                disk_ok,
            )
            self._cleanup_directory(files, quota)

    def _run_periodic_tasks(self) -> None:
        now = time.monotonic()
        with self._lock:
            tasks = list(self._periodic_tasks.values())
        for task in tasks:
            if now < task.next_run:
                continue
            try:
                task.func()
            except Exception:
                logging.exception("Periodic task %s failed", task.name)
            task.next_run = now + task.interval

    @staticmethod
    def _collect_directory_usage(path: str) -> tuple[int, list[tuple[float, str, int]]]:
        total_size = 0
        files: list[tuple[float, str, int]] = []
        for root, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                try:
                    stat = os.stat(file_path)
                except OSError:
                    continue
                total_size += stat.st_size
                files.append((stat.st_mtime, file_path, stat.st_size))
        files.sort()
        return total_size, files

    def _cleanup_directory(self, files: list[tuple[float, str, int]], quota: _DirectoryQuota) -> None:
        total_size = sum(size for _, _, size in files)
        for _, file_path, size in files:
            if quota.max_bytes and total_size <= quota.max_bytes:
                break
            try:
                os.remove(file_path)
                total_size -= size
                logging.info("Removed old file %s during quota cleanup", file_path)
            except FileNotFoundError:
                total_size -= size
            except Exception:
                logging.exception("Failed to remove %s during quota cleanup", file_path)


_global_monitor: Optional[StabilityMonitor] = None
_global_monitor_lock = threading.Lock()


def initialize_global_monitor(
    *,
    role: str = "unknown",
    log_file_path: Optional[str] = None,
    **kwargs,
) -> StabilityMonitor:
    """Initialise the singleton stability monitor if necessary."""

    global _global_monitor
    with _global_monitor_lock:
        if _global_monitor is None:
            _global_monitor = StabilityMonitor(log_file_path=log_file_path, **kwargs)
            _global_monitor.start()
        else:
            if log_file_path is not None:
                _global_monitor.update_log_file_path(log_file_path)
        _global_monitor.configure_role(role=role, log_file_path=log_file_path)
        return _global_monitor


def get_global_monitor() -> StabilityMonitor:
    """Return the global stability monitor, creating it with defaults if required."""
    global _global_monitor
    with _global_monitor_lock:
        if _global_monitor is None:
            _global_monitor = StabilityMonitor()
            _global_monitor.start()
        return _global_monitor
