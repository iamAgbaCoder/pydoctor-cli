"""
pydoctor/performance/parallel.py
─────────────────────────────
Parallel execution utilities for large codebases.
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable, Iterable
from typing import TypeVar

T = TypeVar("T")
R = TypeVar("R")


def run_parallel(
    func: Callable[[T], R], items: Iterable[T], max_workers: int | None = None
) -> list[R]:
    """
    Run a function over a list of items using a thread pool.

    Threads are often better for I/O bound tasks like reading many small files
    or making network requests for vulnerability checks.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(func, items))


def run_parallel_proc(
    func: Callable[[T], R], items: Iterable[T], max_workers: int | None = None
) -> list[R]:
    """
    Run a function over a list of items using a process pool.

    Process pools bypass the GIL and are better for CPU-intensive tasks
    like regex-heavy secret scanning over thousands of lines.
    """
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(func, items))
