from __future__ import annotations

import socket
import sys

from collections.abc import Awaitable, Callable
from typing import final
from . import Stream

async def start_local_redirector(
    handle_tcp_stream: Callable[[Stream], Awaitable[None]],
    handle_udp_stream: Callable[[Stream], Awaitable[None]],
) -> LocalRedirector: ...
@final
class LocalRedirector:
    @staticmethod
    def describe_spec(spec: str) -> None: ...
    def set_intercept(self, spec: str) -> None: ...
    if sys.platform == "darwin":
        async def take_control_socket(self) -> socket.socket: ...
    def close(self) -> None: ...
    async def wait_closed(self) -> None: ...
    @staticmethod
    def unavailable_reason() -> str | None: ...

__all__ = [
    "start_local_redirector",
    "LocalRedirector",
]
