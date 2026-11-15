"""Local admission predicates for the current model call, outside serialized requests."""

from collections.abc import Callable, Generator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field


class DispatchRejected(ValueError):
    """Current local authorization no longer permits beginning provider transport."""

    def __init__(self) -> None:
        super().__init__("The current model dispatch is no longer authorized")


@dataclass
class _Guard:
    check: Callable[[], None] = field(repr=False)
    rejected: bool = False


_guards: ContextVar[tuple[_Guard, ...]] = ContextVar("opsark_ai_dispatch_guards", default=())


@contextmanager
def dispatch_guard(check: Callable[[], None]) -> Generator[_Guard]:
    """Compose predicates and retain cancellation even if an analyzer catches it."""
    guard = _Guard(check)
    token = _guards.set((*_guards.get(), guard))
    try:
        yield guard
    finally:
        _guards.reset(token)


def verify_current_dispatch() -> None:
    """Admit one provider attempt only while all current predicates still pass."""
    guards = _guards.get()
    try:
        for guard in guards:
            if guard.rejected:
                raise DispatchRejected()
            guard.check()
    except Exception:
        for guard in guards:
            guard.rejected = True
        raise DispatchRejected() from None
