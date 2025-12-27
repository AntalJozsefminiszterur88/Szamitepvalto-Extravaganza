
"""Stability monitoring utilities for long-running deployments.

This module provides a reusable monitor that periodically checks resource
consumption, thread health and storage usage. The goal is to detect issues
before they accumulate into long-term failures when the application runs for
extended periods without a restart.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from typing import Callable, Dict, Iterable, Optional

import psutil

ThreadSupplier = Callable[[], Optional[threading.Thread]]
RestartCallback = Callable[[], None]
PeriodicCallable = Callable[[], None]
CleanupCallback = Callable[[], None]


_LOG_LINE_PATTERN = re.compile(
    r"^(?:\[(?P<source>[^\]]+)\]\s+-\s+)?"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})\s+-\s+"
    r"(?P<level>[A-Za-z]+)\s+-\s+"
    r"(?P<thread>[^-]*)\s+-\s+"
    r"(?P<message>.*)$"
)


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
        self._startup_time: float = time.monotonic()
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
        self._stats_received_event = threading.Event()
        self._expected_stats_clients: set[str] = set()
        self._received_stats_clients: set[str] = set()
        self._stats_received_event.set()

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

    def get_report_directory(self) -> Optional[str]:
        with self._lock:
            if not self._log_file_path:
                return None
            return os.path.dirname(os.path.abspath(self._log_file_path))

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

    def add_remote_statistics(self, client_name: str, stats: dict) -> None:
        period_raw = stats.get("period")
        if not period_raw:
            return
        period = str(period_raw)
        methods = list(stats.get("methods", []))
        counters_raw = stats.get("counters", {})
        counters: Dict[str, int] = {}
        if isinstance(counters_raw, dict):
            for key, value in counters_raw.items():
                try:
                    counters[str(key)] = int(value)
                except (TypeError, ValueError):
                    continue
        payload = {
            "methods": methods,
            "counters": counters,
            "received_at": datetime.now(),
        }
        with self._remote_stats_lock:
            latest = self._remote_statistics_latest.setdefault(period, {})
            latest[str(client_name)] = payload
            if self._pending_period == period:
                self._pending_statistics[str(client_name)] = payload
            self._statistics_event.set()
            self._received_stats_clients.add(str(client_name))
            if self._expected_stats_clients and self._expected_stats_clients.issubset(
                self._received_stats_clients
            ):
                self._stats_received_event.set()

    def record_remote_statistics(
        self,
        source: str,
        period: str,
        methods: Iterable[str],
        counters: Dict[str, int],
    ) -> None:
        payload = {
            "period": period,
            "methods": list(methods),
            "counters": {str(k): int(v) for k, v in counters.items()},
        }
        self.add_remote_statistics(source, payload)

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
