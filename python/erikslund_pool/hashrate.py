"""Decaying per-window hash/share rates.

One exponentially-decaying rate per window (1m..7d), so each reflects its own period
rather than one lifetime average.
"""

import math
import threading

# Hashrate windows (seconds) and the field-name suffixes the status file uses.
HASHRATE_WINDOWS: tuple[int, ...] = (60, 300, 900, 3600, 21600, 86400, 604800)
HASHRATE_LABELS: dict[int, str] = {
    60: "1m", 300: "5m", 900: "15m", 3600: "1hr",
    21600: "6hr", 86400: "1d", 604800: "7d",
}
# Shares-per-second windows (a shorter set).
SPS_WINDOWS: tuple[int, ...] = (60, 300, 900, 3600)
SPS_LABELS: dict[int, str] = {60: "1m", 300: "5m", 900: "15m", 3600: "1h"}


def decay_time(value: float, addend: float, elapsed: float, interval: float) -> float:
    """Fold ``addend`` (over ``elapsed`` s) into a decaying per-``interval`` rate.

    With ``addend == 0`` it just ages ``value`` toward zero (an idle-gap read).
    """
    if elapsed <= 0.0:
        return value
    exponent = min(elapsed / interval, 36.0)  # clamp to avoid exp overflow
    proportion = 1.0 - 1.0 / math.exp(exponent)
    return (value + (addend / elapsed) * proportion) / (1.0 + proportion)


class DecayingWindows:
    """A bundle of decaying rates keyed by window length.

    The lock serializes add() (writer) against snapshot() (readers on other threads); on a
    free-threaded build a reader could otherwise observe ``_rates``/``_last`` mid-update.
    """

    def __init__(self, windows: tuple[int, ...], start: float):
        self._windows = windows
        self._rates: dict[int, float] = {window: 0.0 for window in windows}
        self._last = float(start)
        self._lock = threading.Lock()

    def add(self, addend: float, now: float) -> None:
        with self._lock:
            elapsed = now - self._last
            # Guard BEFORE moving _last: callers timestamp outside this lock, so `now` can
            # arrive out of order; advancing _last backward would corrupt every later interval.
            if elapsed <= 0.0:
                return  # sub-tick gap or backward clock: skip rather than divide by ~0 or rewind
            self._last = now
            for window in self._windows:
                self._rates[window] = decay_time(self._rates[window], addend, elapsed, window)

    def snapshot(self, now: float) -> dict[int, float]:
        """Current rate per window, aged to ``now`` (no mutation)."""
        with self._lock:
            elapsed = now - self._last
            if elapsed <= 0.0:
                return dict(self._rates)
            return {window: decay_time(self._rates[window], 0.0, elapsed, window)
                    for window in self._windows}

    def seed(self, rates: dict[int, float], now: float, age_seconds: float) -> None:
        """Adopt rates persisted ``age_seconds`` ago. Backdating the window clock makes the next
        snapshot/add decay the whole downtime, so a restart never resurrects a stale rate."""
        with self._lock:
            self._rates = {window: rates.get(window, 0.0) for window in self._windows}
            self._last = now - max(age_seconds, 0.0)
