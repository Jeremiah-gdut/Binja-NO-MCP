from __future__ import annotations

import ctypes
from dataclasses import dataclass
from os import name as os_name
from threading import Event, Lock, Thread


@dataclass(frozen=True, slots=True)
class ProcessMemorySample:
    private_usage: int
    working_set: int


@dataclass(frozen=True, slots=True)
class MemoryWindow:
    baseline_private_usage: int | None
    peak_private_usage: int | None
    end_private_usage: int | None
    private_usage_delta: int | None
    baseline_working_set: int | None
    peak_working_set: int | None
    end_working_set: int | None
    working_set_delta: int | None

    def to_dict(self) -> dict[str, int | None]:
        return {
            "baseline_private_usage": self.baseline_private_usage,
            "peak_private_usage": self.peak_private_usage,
            "end_private_usage": self.end_private_usage,
            "private_usage_delta": self.private_usage_delta,
            "baseline_working_set": self.baseline_working_set,
            "peak_working_set": self.peak_working_set,
            "end_working_set": self.end_working_set,
            "working_set_delta": self.working_set_delta,
        }


def _process_memory_sample() -> ProcessMemorySample | None:
    if os_name != "nt":
        return None

    class ProcessMemoryCountersEx(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(counters)
    get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
    get_process_memory_info.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessMemoryCountersEx), ctypes.c_ulong]
    get_process_memory_info.restype = ctypes.c_int
    process = ctypes.windll.kernel32.GetCurrentProcess()
    if not get_process_memory_info(process, ctypes.byref(counters), counters.cb):
        return None
    return ProcessMemorySample(private_usage=int(counters.PrivateUsage), working_set=int(counters.WorkingSetSize))


class ProcessMemoryMonitor:
    """Sample only process-level memory; it never reads Binary Ninja objects."""

    def __init__(self, private_usage_limit_bytes: int, sample_interval_seconds: float = 0.2) -> None:
        self._private_usage_limit_bytes = private_usage_limit_bytes
        self._sample_interval_seconds = sample_interval_seconds
        self._stop_event = Event()
        self._lock = Lock()
        self._thread: Thread | None = None
        self._latest: ProcessMemorySample | None = None
        self._baseline: ProcessMemorySample | None = None
        self._peak: ProcessMemorySample | None = None
        self._exceeded = False

    @property
    def exceeded(self) -> bool:
        with self._lock:
            return self._exceeded

    def start(self) -> None:
        if self._thread is not None:
            return
        self._capture()
        self._thread = Thread(target=self._run, name="BinjaNoMcpMemoryMonitor", daemon=True)
        self._thread.start()

    def begin_window(self) -> None:
        self._capture()
        with self._lock:
            self._baseline = self._latest
            self._peak = self._latest
            self._exceeded = False

    def end_window(self) -> MemoryWindow:
        self._capture()
        with self._lock:
            baseline = self._baseline
            peak = self._peak
            end = self._latest
        return MemoryWindow(
            baseline_private_usage=None if baseline is None else baseline.private_usage,
            peak_private_usage=None if peak is None else peak.private_usage,
            end_private_usage=None if end is None else end.private_usage,
            private_usage_delta=_peak_delta(baseline, peak, "private_usage"),
            baseline_working_set=None if baseline is None else baseline.working_set,
            peak_working_set=None if peak is None else peak.working_set,
            end_working_set=None if end is None else end.working_set,
            working_set_delta=_peak_delta(baseline, peak, "working_set"),
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._sample_interval_seconds * 2)

    def _run(self) -> None:
        while not self._stop_event.wait(self._sample_interval_seconds):
            self._capture()

    def _capture(self) -> None:
        try:
            sample = _process_memory_sample()
        except (OSError, ctypes.ArgumentError):
            return
        if sample is None:
            return
        with self._lock:
            self._latest = sample
            if self._peak is None or sample.private_usage > self._peak.private_usage:
                self._peak = sample
            if (
                self._baseline is not None
                and self._baseline.private_usage < self._private_usage_limit_bytes <= sample.private_usage
            ):
                self._exceeded = True


def _peak_delta(
    baseline: ProcessMemorySample | None,
    peak: ProcessMemorySample | None,
    attribute: str,
) -> int | None:
    if baseline is None or peak is None:
        return None
    return int(getattr(peak, attribute) - getattr(baseline, attribute))
