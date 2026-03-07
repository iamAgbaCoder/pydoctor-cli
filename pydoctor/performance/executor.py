"""
pydoctor/performance/executor.py
──────────────────────────────────
Parallel task execution helpers.

Wraps ``concurrent.futures.ThreadPoolExecutor`` with a clean interface
that PyDoctor's scanners use to fan-out work across multiple packages or
files concurrently.

Why threads and not processes?
Most scanner work is I/O-bound (network calls to OSV/PyPI, reading files).
Threads share the GIL effectively here — no need for multiprocessing overhead.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import Callable, Iterable, TypeVar, Any

from pydoctor.config.settings import MAX_WORKERS

T = TypeVar("T")


# ──────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────


def run_parallel(
    fn: Callable[..., T],
    items: Iterable[Any],
    *,
    workers: int = MAX_WORKERS,
    timeout: float | None = None,
) -> list[T]:
    """
    Apply ``fn`` to each item in ``items`` concurrently.

    Parameters
    ----------
    fn:      The function to call for each item.
             Called as ``fn(item)`` — use ``functools.partial`` for extra args.
    items:   Iterable of items to process.
    workers: Maximum number of concurrent worker threads.
    timeout: Optional per-future wait timeout in seconds.

    Returns
    -------
    list[T]
        Results in an unspecified (completion) order.
        Exceptions raised by ``fn`` are caught and silently dropped to
        ensure one failing item doesn't abort the whole batch.
    """
    results: list[T] = []
    item_list = list(items)

    if not item_list:
        return results

    with ThreadPoolExecutor(max_workers=min(workers, len(item_list))) as executor:
        future_map: dict[Future, Any] = {executor.submit(fn, item): item for item in item_list}
        for future in as_completed(future_map, timeout=timeout):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception:
                # Individual item failure — skip it
                pass

    return results


def run_parallel_dict(
    fn: Callable[[str, Any], T],
    mapping: dict[str, Any],
    *,
    workers: int = MAX_WORKERS,
) -> list[T]:
    """
    Like ``run_parallel`` but operates on a dict, passing key and value to fn.

    Parameters
    ----------
    fn:      Called as ``fn(key, value)`` for each dict entry.
    mapping: Input dictionary.
    workers: Max threads.

    Returns
    -------
    list[T]
    """
    from functools import partial

    results: list[T] = []
    if not mapping:
        return results

    with ThreadPoolExecutor(max_workers=min(workers, len(mapping))) as executor:
        futures = {executor.submit(fn, k, v): k for k, v in mapping.items()}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception:
                pass

    return results


def timed(fn: Callable[..., T], *args, **kwargs) -> tuple[T, float]:
    """
    Call ``fn(*args, **kwargs)`` and return ``(result, elapsed_ms)``.

    Parameters
    ----------
    fn:     Function to call.
    *args:  Positional arguments.
    **kwargs: Keyword arguments.

    Returns
    -------
    tuple[T, float]
        The function's return value and elapsed time in milliseconds.
    """
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed_ms = (time.perf_counter() - start) * 1000
    return result, elapsed_ms
