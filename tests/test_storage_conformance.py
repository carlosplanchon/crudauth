"""C17: every AbstractSessionStorage backend passes the same behavioral suite."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from crudauth.storage.backends.memory import MemorySessionStorage
from crudauth.storage.backends.redis import RedisSessionStorage
from crudauth.transports.session.schemas import SessionData


def _fakeredis_client():
    import fakeredis.aioredis

    return fakeredis.aioredis.FakeRedis()


@pytest.fixture(params=["memory", "redis"])
async def storage(request) -> AsyncIterator:
    if request.param == "memory":
        yield MemorySessionStorage(prefix="t:", expiration=100)
    else:
        store: RedisSessionStorage[SessionData] = RedisSessionStorage(
            prefix="t:", expiration=100, client=_fakeredis_client()
        )
        yield store
        await store.close()


async def test_create_get_roundtrip(storage) -> None:
    sid = await storage.create(SessionData(user_id=1), session_id="s1")
    assert sid == "s1"
    got = await storage.get("s1", SessionData)
    assert got is not None and got.user_id == 1


async def test_exists_and_delete(storage) -> None:
    await storage.create(SessionData(user_id=1), session_id="s1")
    assert await storage.exists("s1") is True
    assert await storage.delete("s1") is True
    assert await storage.exists("s1") is False
    assert await storage.get("s1", SessionData) is None


async def test_update(storage) -> None:
    await storage.create(SessionData(user_id=1), session_id="s1")
    data = await storage.get("s1", SessionData)
    data.metadata["x"] = "y"
    assert await storage.update("s1", data) is True
    again = await storage.get("s1", SessionData)
    assert again.metadata["x"] == "y"
    # update on a missing key is False
    assert await storage.update("missing", SessionData(user_id=2)) is False


async def test_extend(storage) -> None:
    await storage.create(SessionData(user_id=1), session_id="s1", expiration=50)
    assert await storage.extend("s1", 100) is True


async def test_get_user_sessions(storage) -> None:
    await storage.create(SessionData(user_id=7), session_id="a")
    await storage.create(SessionData(user_id=7), session_id="b")
    await storage.create(SessionData(user_id=8), session_id="c")
    ids = set(await storage.get_user_sessions(7))
    assert ids == {"a", "b"}


async def test_delete_with_user_id_updates_index(storage) -> None:
    # #2: passing user_id lets delete drop the session from the user index
    # without re-reading the record; the index stays consistent.
    await storage.create(SessionData(user_id=7), session_id="a")
    await storage.create(SessionData(user_id=7), session_id="b")
    assert await storage.delete("a", user_id=7) is True
    assert set(await storage.get_user_sessions(7)) == {"b"}


async def test_delete_without_user_id_still_updates_index(storage) -> None:
    # logout path: only the session id is known; delete reads the owner itself.
    await storage.create(SessionData(user_id=9), session_id="x")
    assert await storage.delete("x") is True
    assert await storage.get_user_sessions(9) == []
