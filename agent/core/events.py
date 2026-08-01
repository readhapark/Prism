from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, AsyncIterator

from agent.models import AgentEvent


class EventBus:
    """In-process pub/sub for live narrative SSE streams."""

    def __init__(self) -> None:
        self._subs: dict[str, list[asyncio.Queue[AgentEvent | None]]] = defaultdict(list)
        self._history: dict[str, list[AgentEvent]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def publish(self, event: AgentEvent) -> None:
        async with self._lock:
            self._history[event.run_id].append(event)
            queues = list(self._subs.get(event.run_id, []))
        for q in queues:
            await q.put(event)

    async def subscribe(self, run_id: str) -> AsyncIterator[AgentEvent]:
        q: asyncio.Queue[AgentEvent | None] = asyncio.Queue()
        async with self._lock:
            # Replay history first via queue
            for ev in self._history.get(run_id, []):
                await q.put(ev)
            self._subs[run_id].append(q)
        try:
            while True:
                item = await q.get()
                if item is None:
                    break
                yield item
        finally:
            async with self._lock:
                if q in self._subs[run_id]:
                    self._subs[run_id].remove(q)

    async def close(self, run_id: str) -> None:
        async with self._lock:
            for q in self._subs.get(run_id, []):
                await q.put(None)

    def history(self, run_id: str) -> list[AgentEvent]:
        return list(self._history.get(run_id, []))


bus = EventBus()