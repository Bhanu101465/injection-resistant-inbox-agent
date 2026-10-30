"""
Stage / Pipeline interface (architecture-prep).

These abstract base classes define the contract for pipeline stages that will
be added in later steps (e.g. detection, sanitisation, policy enforcement).
No concrete implementations live here yet — this file is definitions-only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

# Generic type vars for input / output of a stage
In = TypeVar("In")
Out = TypeVar("Out")


class StageContext(BaseModel):
    """Shared context passed through every stage in a pipeline run.

    Stages may read from and write to this object to propagate metadata
    (e.g. taint flags, detection verdicts) without coupling stage logic
    directly to each other.
    """

    email_id: str = ""
    task_id: str = ""
    flags: dict[str, Any] = {}
    """Arbitrary key-value flags set by upstream stages."""
    trace: list[str] = []
    """Ordered list of stage names that have already processed this context."""


class Stage(ABC, Generic[In, Out]):
    """Abstract base for a single processing stage.

    Type parameters
    ---------------
    In  : The type consumed by this stage.
    Out : The type produced by this stage.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable identifier for this stage (used in traces)."""

    @abstractmethod
    def process(self, input: In, ctx: StageContext) -> Out:
        """Execute this stage.

        Parameters
        ----------
        input : Input artifact (e.g. an Email or ExtractedEmail).
        ctx   : Shared pipeline context; mutate ``ctx.flags`` as needed.

        Returns
        -------
        Out
            The transformed / enriched artifact passed to the next stage.
        """


class Pipeline(Generic[In, Out]):
    """Ordered sequence of ``Stage`` objects run left-to-right.

    The output type of stage N must be compatible with the input type of
    stage N+1.  Python's type system cannot enforce this statically for
    heterogeneous pipelines, so the responsibility falls on the caller.

    Parameters
    ----------
    stages : Ordered list of Stage instances.
    """

    def __init__(self, stages: list[Stage]) -> None:  # type: ignore[type-arg]
        self._stages = stages

    @property
    def stages(self) -> list[Stage]:  # type: ignore[type-arg]
        return list(self._stages)

    def run(self, input: In, ctx: StageContext | None = None) -> Out:
        """Execute all stages in order and return the final output.

        Parameters
        ----------
        input : The initial input artifact.
        ctx   : Optional shared context; a fresh one is created if not given.

        Returns
        -------
        Out
            The artifact produced by the last stage.
        """
        if ctx is None:
            ctx = StageContext()
        result: Any = input
        for stage in self._stages:
            ctx.trace.append(stage.name)
            result = stage.process(result, ctx)
        return result  # type: ignore[return-value]
