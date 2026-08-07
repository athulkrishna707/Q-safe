"""
Q-SAFE Async Event Queue
==========================
Central event bus connecting the enforcement engine to the autonomous agents.

The enforcement middleware enqueues every verdict event here.
The profiler_agent and oracle_agent consume from this queue asynchronously.

DESIGN BOUNDARY:
  The queue is the hard separation between the synchronous hot path and
  the async AI/analytics pipeline. Nothing in agents/ may enter the hot path.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from core.models import EventRecord


class EventQueue:
    """
    Async FIFO event queue backed by asyncio.Queue.

    Producers (enforcement middleware): call enqueue() — non-blocking.
    Consumers (agents): call dequeue() — async, blocks until event available.

    Max size of 10,000 prevents unbounded memory growth under attack floods.
    """

    def __init__(self, maxsize: int = 10_000) -> None:
        self._queue: asyncio.Queue[EventRecord] = asyncio.Queue(maxsize=maxsize)

    async def enqueue(self, event: EventRecord) -> None:
        """
        Add an event to the queue.

        Non-blocking: if the queue is full, the oldest event is silently dropped
        to prevent back-pressure from ever reaching the enforcement hot path.

        Args:
            event: EventRecord to enqueue.
        """
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            # Drop oldest and retry — agents can't keep up, but enforcement must not slow
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass  # Silently discard under extreme load

    async def dequeue(self) -> EventRecord:
        """
        Retrieve the next event from the queue (async, blocking).

        Args: None

        Returns:
            Next EventRecord in FIFO order.
        """
        return await self._queue.get()

    async def dequeue_batch(self, max_items: int = 50) -> list[EventRecord]:
        """
        Drain up to max_items events without blocking (for batch processing).

        Args:
            max_items: Maximum events to dequeue in one batch.

        Returns:
            List of EventRecords (may be empty if queue is empty).
        """
        items: list[EventRecord] = []
        for _ in range(max_items):
            try:
                items.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return items

    def qsize(self) -> int:
        """Return current queue size."""
        return self._queue.qsize()

    def empty(self) -> bool:
        """Return True if queue is empty."""
        return self._queue.empty()


# ── Module-Level Singleton ────────────────────────────────────────────────────

_event_queue: Optional[EventQueue] = None


def get_event_queue() -> EventQueue:
    """
    Return the process-wide EventQueue singleton.

    Returns:
        Shared EventQueue instance.
    """
    global _event_queue
    if _event_queue is None:
        _event_queue = EventQueue()
    return _event_queue
