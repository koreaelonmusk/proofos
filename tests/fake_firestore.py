"""An in-process stand-in for the Firestore client.

This exists to test the *adapter's* logic deterministically and without
credentials: sequence assignment, chain linkage, idempotency, transaction
rollback, and how the adapter reacts to storage faults.

It proves nothing about Firestore itself. Real write/read against a real
project remains unproven, and no test here may be read as evidence of cloud
persistence.

Two behaviours are modelled deliberately because the adapter depends on them:

* writes inside a transaction are buffered and applied only at commit, so a
  failed append leaves nothing behind;
* ``create`` on an existing document raises ``google.api_core.exceptions
  .AlreadyExists`` -- the real exception type, so the adapter's error handling
  is exercised against the class it will actually see.
"""

from __future__ import annotations

from typing import Any, Callable

from google.api_core.exceptions import AlreadyExists, ServiceUnavailable


class FakeSnapshot:
    def __init__(self, exists: bool, data: dict | None):
        self.exists = exists
        self._data = data

    def to_dict(self):
        return dict(self._data) if isinstance(self._data, dict) else self._data


class FakeDocument:
    def __init__(self, client: "FakeFirestore", path: str):
        self._client = client
        self.path = path

    def collection(self, name: str) -> "FakeCollection":
        return FakeCollection(self._client, f"{self.path}/{name}")

    def get(self, transaction=None) -> FakeSnapshot:
        self._client.reads.append(self.path)
        if self._client.read_error is not None:
            raise self._client.read_error
        if self.path in self._client.docs:
            return FakeSnapshot(True, self._client.docs[self.path])
        return FakeSnapshot(False, None)

    def create(self, data: dict) -> None:
        if self.path in self._client.docs:
            raise AlreadyExists(f"document already exists: {self.path}")
        self._client.docs[self.path] = dict(data)

    def set(self, data: dict, merge: bool = False) -> None:
        if merge and self.path in self._client.docs:
            self._client.docs[self.path].update(data)
        else:
            self._client.docs[self.path] = dict(data)

    def delete(self) -> None:
        self._client.docs.pop(self.path, None)


class FakeCollection:
    def __init__(self, client: "FakeFirestore", path: str):
        self._client = client
        self.path = path

    def document(self, doc_id: str) -> FakeDocument:
        return FakeDocument(self._client, f"{self.path}/{doc_id}")

    def stream(self):
        if self._client.stream_error is not None:
            raise self._client.stream_error
        prefix = f"{self.path}/"
        paths = [
            path
            for path in self._client.docs
            if path.startswith(prefix) and "/" not in path[len(prefix) :]
        ]
        # Firestore makes no ordering promise the adapter is allowed to rely
        # on, so hand documents back in an order that is deliberately not the
        # sequence order.
        for path in self._client.stream_order(paths):
            yield FakeSnapshot(True, self._client.docs[path])


class FakeTransaction:
    """Buffers writes and applies them only on commit."""

    def __init__(self, client: "FakeFirestore"):
        self._client = client
        self._writes: list[tuple[str, FakeDocument, dict, bool]] = []

    def create(self, ref: FakeDocument, data: dict) -> None:
        self._writes.append(("create", ref, dict(data), False))

    def set(self, ref: FakeDocument, data: dict, merge: bool = False) -> None:
        self._writes.append(("set", ref, dict(data), merge))

    def commit(self) -> None:
        if self._client.commit_error is not None:
            raise self._client.commit_error
        # Validate every create before applying anything, so a conflicting
        # write cannot leave a half-applied transaction behind.
        for kind, ref, _, _ in self._writes:
            if kind == "create" and ref.path in self._client.docs:
                raise AlreadyExists(f"document already exists: {ref.path}")
        for kind, ref, data, merge in self._writes:
            if kind == "create":
                ref.create(data)
            else:
                ref.set(data, merge=merge)
        self._writes.clear()


class FakeFirestore:
    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}
        self.reads: list[str] = []
        self.read_error: Exception | None = None
        self.stream_error: Exception | None = None
        self.commit_error: Exception | None = None
        self.before_commit: Callable[[], None] | None = None
        self._stream_order: Callable[[list[str]], list[str]] = lambda p: sorted(
            p, reverse=True
        )

    def collection(self, name: str) -> FakeCollection:
        return FakeCollection(self, name)

    def transaction(self) -> FakeTransaction:
        return FakeTransaction(self)

    def stream_order(self, paths: list[str]) -> list[str]:
        return self._stream_order(paths)

    def set_stream_order(self, fn: Callable[[list[str]], list[str]]) -> None:
        self._stream_order = fn

    # -- test helpers -----------------------------------------------------

    def event_paths(self, execution_id: str) -> list[str]:
        prefix = f"executions/{execution_id}/events/"
        return sorted(p for p in self.docs if p.startswith(prefix))

    def event_records(self, execution_id: str) -> list[dict]:
        return [self.docs[p] for p in self.event_paths(execution_id)]

    def unavailable(self) -> Exception:
        return ServiceUnavailable("firestore is unreachable")


def fake_transactional(fn: Callable) -> Callable:
    """Stand-in for ``firestore.transactional``.

    Runs the operation and commits. If the operation raises, nothing is
    committed, which is the property the adapter relies on for failed appends.
    """

    def wrapper(transaction: FakeTransaction):
        result = fn(transaction)
        if transaction._client.before_commit is not None:
            hook = transaction._client.before_commit
            transaction._client.before_commit = None
            hook()
        transaction.commit()
        return result

    return wrapper
