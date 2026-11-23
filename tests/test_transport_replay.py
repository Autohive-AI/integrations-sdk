"""Wire-level regressions for aiohttp's implicit pooled-connection replay."""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from autohive_integrations_sdk import ExecutionContext


@asynccontextmanager
async def disconnecting_server():
    """Accept a request, then drop its response once on a reused connection."""
    state = SimpleNamespace(requests=[], accepted_deletions=0, deleted=False)
    writers = set()
    tasks = set()

    async def handle(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        writers.add(writer)
        connection = writer.get_extra_info("peername")
        try:
            while True:
                headers = await reader.readuntil(b"\r\n\r\n")
                method, path, _ = (
                    headers.split(b"\r\n", 1)[0].decode("ascii").split(" ")
                )
                state.requests.append((method, path, connection))
                if method == "DELETE":
                    if not state.deleted:
                        state.deleted = True
                        state.accepted_deletions += 1
                        # The mutation happened, but its response never reached the caller.
                        writer.close()
                        return
                    status, body = b"404 Not Found", b'{"error":"already deleted"}'
                elif (
                    path == "/flaky"
                    and sum(path == entry[1] for entry in state.requests) == 1
                ):
                    writer.close()
                    return
                else:
                    status, body = b"200 OK", b'{"ok":true}'
                writer.write(
                    b"HTTP/1.1 "
                    + status
                    + b"\r\nContent-Type: application/json\r\nContent-Length: "
                    + str(len(body)).encode("ascii")
                    + b"\r\nConnection: keep-alive\r\n\r\n"
                    + body
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            writers.discard(writer)
            tasks.discard(task)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    state.url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    try:
        yield state
    finally:
        server.close()
        await server.wait_closed()
        for writer in list(writers):
            writer.close()
        if tasks:
            await asyncio.wait_for(asyncio.gather(*list(tasks)), timeout=5)


@pytest.mark.parametrize("eager_session", [False, True])
async def test_delete_disconnect_is_not_replayed_after_server_accepts_mutation(
    eager_session,
):
    async with disconnecting_server() as server:
        context = ExecutionContext(request_config={"max_retries": 3, "timeout": 5})
        if eager_session:
            await context.__aenter__()
        try:
            assert (await context.fetch(f"{server.url}/prime")).status == 200
            with pytest.raises(aiohttp.ClientConnectionError):
                await context.fetch(
                    f"{server.url}/order", method="DELETE", retry_count=3
                )
        finally:
            await context.__aexit__(None, None, None)

        assert [entry[:2] for entry in server.requests] == [
            ("GET", "/prime"),
            ("DELETE", "/order"),
        ]
        assert server.accepted_deletions == 1
        assert server.requests[0][2] == server.requests[1][2], (
            "DELETE must exercise the reused-connection path"
        )


async def test_get_disconnect_uses_sdk_backoff_instead_of_implicit_transport_replay():
    async with disconnecting_server() as server:
        async with ExecutionContext(
            request_config={"max_retries": 1, "timeout": 5}
        ) as context:
            assert (await context.fetch(f"{server.url}/prime")).status == 200
            with patch(
                "autohive_integrations_sdk.integration.asyncio.sleep",
                new_callable=AsyncMock,
            ) as sleep:
                response = await context.fetch(f"{server.url}/flaky")
            assert response.status == 200
            assert response.data == {"ok": True}
            sleep.assert_awaited_once_with(1)

        assert [entry[:2] for entry in server.requests] == [
            ("GET", "/prime"),
            ("GET", "/flaky"),
            ("GET", "/flaky"),
        ]
        assert server.requests[0][2] == server.requests[1][2]
        assert server.requests[1][2] != server.requests[2][2]
