"""Bounded process/image registry for recursive Frida child-gating runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .events import ObservedProcess, ProcessImage, ProcessTreeResult


class ProcessTreeError(RuntimeError):
    """Base class for invalid process-tree transitions."""


class UnknownProcessParent(ProcessTreeError):
    """Raised when Frida reports a child outside the admitted tree."""


class DuplicateProcessImage(ProcessTreeError):
    """Raised for a duplicate/non-exec image transition on an existing PID."""


class ProcessTreeLimitExceeded(ProcessTreeError):
    """A process or image cap was reached; the gated child must be released."""

    def __init__(self, limit: str, maximum: int):
        super().__init__(f"{limit} limit exceeded ({maximum})")
        self.limit = limit
        self.maximum = maximum


@dataclass(frozen=True, slots=True)
class ImageAdmission:
    instance: str
    pid: int
    parent_pid: int | None
    depth: int
    root: bool
    origin: str
    identifier: str | None
    start_token: str | None


@dataclass(slots=True)
class _ImageState:
    instance: str
    pid: int
    origin: str
    identifier: str | None
    instrumentation_status: str = "NOT_DETECTED"
    instrumented: bool = False
    coverage_complete: bool = False
    detach_reason: str | None = None

    def freeze(self) -> ProcessImage:
        return ProcessImage(
            instance=self.instance,
            pid=self.pid,
            origin=self.origin,
            identifier=self.identifier,
            instrumentation_status=self.instrumentation_status,
            instrumented=self.instrumented,
            coverage_complete=self.coverage_complete,
            detach_reason=self.detach_reason,
        )


@dataclass(slots=True)
class _ProcessState:
    pid: int
    parent_pid: int | None
    depth: int
    root: bool
    start_token: str | None
    images: list[_ImageState] = field(default_factory=list)
    active_at_root_exit: bool = False

    @property
    def current(self) -> _ImageState:
        return self.images[-1]


class ProcessTreeRegistry:
    """Pure bounded state machine for one application process tree.

    The launcher is intentionally never admitted. A PID is one observed
    process; every exec transition for that PID creates a new image and stream.
    """

    def __init__(
        self,
        *,
        follow_children: bool = True,
        max_followed_processes: int = 256,
        max_process_images: int = 1024,
        start_token_reader: Callable[[int], str | None] | None = None,
    ) -> None:
        for name, value in (
            ("max_followed_processes", max_followed_processes),
            ("max_process_images", max_process_images),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not isinstance(follow_children, bool):
            raise TypeError("follow_children must be a boolean")
        self.follow_children = follow_children
        self.max_followed_processes = max_followed_processes
        self.max_process_images = max_process_images
        self._start_token_reader = start_token_reader
        self._root_pid: int | None = None
        self._processes: dict[int, _ProcessState] = {}
        self._images: dict[str, _ImageState] = {}
        self._complete = True
        self._omitted_images = 0

    @property
    def root_pid(self) -> int | None:
        return self._root_pid

    @property
    def process_count(self) -> int:
        return len(self._processes)

    @property
    def image_count(self) -> int:
        return len(self._images)

    @property
    def complete(self) -> bool:
        return self._complete and all(
            image.coverage_complete
            for process in self._processes.values()
            for image in process.images
        )

    @property
    def omitted_images(self) -> int:
        return self._omitted_images

    def has_pid(self, pid: int) -> bool:
        return pid in self._processes

    def has_instance(self, instance: str) -> bool:
        return instance in self._images

    def current_instance(self, pid: int) -> str | None:
        process = self._processes.get(pid)
        return None if process is None else process.current.instance

    def start_token(self, pid: int) -> str | None:
        process = self._processes.get(pid)
        return None if process is None else process.start_token

    def admission(self, instance: str) -> ImageAdmission:
        image = self._require_image(instance)
        process = self._processes[image.pid]
        return ImageAdmission(
            image.instance,
            image.pid,
            process.parent_pid,
            process.depth,
            process.root,
            image.origin,
            image.identifier,
            process.start_token,
        )

    def admit_root(
        self,
        pid: int,
        *,
        origin: str = "spawn",
        identifier: str | None = None,
        start_token: str | None = None,
    ) -> ImageAdmission:
        self._validate_pid(pid)
        if self._root_pid is not None:
            raise DuplicateProcessImage("root process is already admitted")
        return self._admit_new_process(
            pid,
            parent_pid=None,
            depth=0,
            root=True,
            origin=origin,
            identifier=identifier,
            start_token=start_token,
        )

    def admit_child(
        self,
        pid: int,
        parent_pid: int | None,
        *,
        origin: str,
        identifier: str | None = None,
        start_token: str | None = None,
    ) -> ImageAdmission:
        self._validate_pid(pid)
        if not isinstance(origin, str) or not origin:
            raise ProcessTreeError("child origin must be a non-empty string")

        existing = self._processes.get(pid)
        if existing is not None:
            if (
                existing.start_token is not None
                and start_token is not None
                and existing.start_token != start_token
            ):
                raise DuplicateProcessImage(
                    f"PID {pid} start token changed across an alleged exec"
                )
            if existing.start_token is None and start_token is not None:
                existing.start_token = start_token
            if origin != "exec":
                raise DuplicateProcessImage(
                    f"PID {pid} already exists and child origin is not exec"
                )
            if parent_pid not in {None, pid, existing.parent_pid}:
                raise UnknownProcessParent(
                    f"exec image {pid} reported unexpected parent {parent_pid}"
                )
            return self._admit_exec(existing, origin, identifier)

        if parent_pid is None or parent_pid not in self._processes:
            raise UnknownProcessParent(
                f"child {pid} has parent {parent_pid}, which is not in scope"
            )
        parent = self._processes[parent_pid]
        return self._admit_new_process(
            pid,
            parent_pid=parent_pid,
            depth=parent.depth + 1,
            root=False,
            origin=origin,
            identifier=identifier,
            start_token=start_token,
        )

    def _admit_new_process(
        self,
        pid: int,
        *,
        parent_pid: int | None,
        depth: int,
        root: bool,
        origin: str,
        identifier: str | None,
        start_token: str | None,
    ) -> ImageAdmission:
        if len(self._processes) >= self.max_followed_processes:
            self.note_omitted_image()
            raise ProcessTreeLimitExceeded(
                "max_followed_processes", self.max_followed_processes
            )
        self._check_image_capacity()
        token = start_token
        if token is None and self._start_token_reader is not None:
            token = self._start_token_reader(pid)
        process = _ProcessState(pid, parent_pid, depth, root, token)
        self._processes[pid] = process
        if root:
            self._root_pid = pid
        return self._append_image(process, origin, identifier)

    def _admit_exec(
        self, process: _ProcessState, origin: str, identifier: str | None
    ) -> ImageAdmission:
        self._check_image_capacity()
        if process.current.detach_reason is None:
            process.current.detach_reason = "process-replaced"
        return self._append_image(process, origin, identifier)

    def _append_image(
        self, process: _ProcessState, origin: str, identifier: str | None
    ) -> ImageAdmission:
        generation = len(process.images) + 1
        instance = f"p{process.pid}-i{generation}"
        image = _ImageState(instance, process.pid, origin, identifier)
        process.images.append(image)
        self._images[instance] = image
        return self.admission(instance)

    def _check_image_capacity(self) -> None:
        if len(self._images) >= self.max_process_images:
            self.note_omitted_image()
            raise ProcessTreeLimitExceeded(
                "max_process_images", self.max_process_images
            )

    def note_omitted_image(self) -> None:
        self._omitted_images += 1
        self._complete = False

    def mark_instrumented(self, instance: str) -> None:
        image = self._require_image(instance)
        image.instrumented = True
        image.coverage_complete = True

    def mark_status(self, instance: str, status: str) -> None:
        if status not in {
            "FAILED", "PARTIAL", "ACTIVE", "DETECTED_UNSUPPORTED", "NOT_DETECTED",
        }:
            raise ValueError(f"invalid instrumentation status: {status}")
        self._require_image(instance).instrumentation_status = status

    def mark_coverage_loss(self, instance: str, reason: str | None = None) -> None:
        image = self._require_image(instance)
        image.instrumentation_status = "PARTIAL"
        image.instrumented = False
        image.coverage_complete = False
        if reason and image.detach_reason is None:
            image.detach_reason = reason
        self._complete = False

    def mark_detached(self, instance: str, reason: str) -> None:
        image = self._require_image(instance)
        image.detach_reason = reason

    def mark_active_at_root_exit(self, pid: int) -> None:
        process = self._processes.get(pid)
        if process is not None:
            process.active_at_root_exit = True

    def deepest_first(self) -> tuple[ImageAdmission, ...]:
        """Return one current image per process in safe cleanup order."""
        processes = sorted(
            self._processes.values(), key=lambda item: (-item.depth, -item.pid)
        )
        return tuple(self.admission(process.current.instance) for process in processes)

    def freeze(self, *, fatal_failure: bool = False) -> ProcessTreeResult:
        processes = tuple(
            ObservedProcess(
                pid=process.pid,
                parent_pid=process.parent_pid,
                depth=process.depth,
                root=process.root,
                images=tuple(image.freeze() for image in process.images),
                active_at_root_exit=process.active_at_root_exit,
            )
            for process in sorted(
                self._processes.values(), key=lambda item: (item.depth, item.pid)
            )
        )
        return ProcessTreeResult(
            follow_children=self.follow_children,
            root_pid=self._root_pid,
            complete=self.complete and not fatal_failure,
            processes=processes,
            max_followed_processes=self.max_followed_processes,
            max_process_images=self.max_process_images,
            omitted_images=self._omitted_images,
        )

    def _require_image(self, instance: str) -> _ImageState:
        try:
            return self._images[instance]
        except KeyError as exc:
            raise ProcessTreeError(f"unknown process image: {instance}") from exc

    @staticmethod
    def _validate_pid(pid: int) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ProcessTreeError("process pid must be a positive integer")


def aggregate_instrumentation_status(
    tree: ProcessTreeResult, *, fatal_failure: bool = False
) -> str:
    """Apply the deterministic tree-wide status reduction from the contract."""
    statuses = [
        image.instrumentation_status
        for process in tree.processes
        for image in process.images
    ]
    if fatal_failure or "FAILED" in statuses:
        return "FAILED"
    if not tree.complete or "PARTIAL" in statuses:
        return "PARTIAL"
    if "ACTIVE" in statuses:
        return "PARTIAL" if "DETECTED_UNSUPPORTED" in statuses else "ACTIVE"
    if "DETECTED_UNSUPPORTED" in statuses:
        return "DETECTED_UNSUPPORTED"
    return "NOT_DETECTED"


__all__ = [
    "DuplicateProcessImage",
    "ImageAdmission",
    "ProcessTreeError",
    "ProcessTreeLimitExceeded",
    "ProcessTreeRegistry",
    "UnknownProcessParent",
    "aggregate_instrumentation_status",
]
