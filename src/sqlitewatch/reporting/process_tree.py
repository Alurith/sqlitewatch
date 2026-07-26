"""Shared process-tree serialization and terminal-safe rendering."""

from __future__ import annotations

from ..events import ProcessTreeResult
from .sanitize import terminal_safe


def process_tree_to_dict(tree: ProcessTreeResult) -> dict[str, object]:
    return {
        "follow_children": tree.follow_children,
        "scope": "recursive" if tree.follow_children else "root_only",
        "root_pid": tree.root_pid,
        "complete": tree.complete,
        "process_count": tree.process_count,
        "image_count": tree.image_count,
        "active_at_root_exit": tree.active_at_root_exit,
        "omitted_images": tree.omitted_images,
        "limits": {
            "max_followed_processes": tree.max_followed_processes,
            "max_process_images": tree.max_process_images,
        },
        "processes": [
            {
                "pid": process.pid,
                "parent_pid": process.parent_pid,
                "depth": process.depth,
                "root": process.root,
                "active_at_root_exit": process.active_at_root_exit,
                "images": [
                    {
                        "instance": image.instance,
                        "origin": image.origin,
                        "identifier": image.identifier,
                        "status": image.instrumentation_status,
                        "instrumented": image.instrumented,
                        "coverage_complete": image.coverage_complete,
                        "detach_reason": image.detach_reason,
                    }
                    for image in process.images
                ],
            }
            for process in tree.processes
        ],
    }


def render_process_tree_terminal(tree: ProcessTreeResult) -> list[str]:
    lines = [
        "Process tree",
        "  Policy: " + ("recursive follow" if tree.follow_children else "root only"),
        f"  Root PID: {tree.root_pid}",
        f"  Coverage complete: {tree.complete}",
        f"  Processes/images: {tree.process_count}/{tree.image_count}",
        f"  Active at root exit: {tree.active_at_root_exit}",
        f"  Omitted images: {tree.omitted_images}",
        "  Limits: "
        f"processes={tree.max_followed_processes} images={tree.max_process_images}",
    ]
    if not tree.processes:
        lines.append("  Inventory: none")
        return lines
    lines.append("  Inventory")
    for process in tree.processes:
        parent = "none" if process.parent_pid is None else str(process.parent_pid)
        lines.append(
            f"    pid={process.pid} parent={parent} depth={process.depth} "
            f"root={process.root} active_at_root_exit={process.active_at_root_exit}"
        )
        for image in process.images:
            identifier = terminal_safe(image.identifier or "unavailable")
            detach = terminal_safe(image.detach_reason or "none")
            lines.append(
                "      "
                f"instance={terminal_safe(image.instance)} "
                f"origin={terminal_safe(image.origin)} "
                f"identifier={identifier} status={terminal_safe(image.instrumentation_status)} "
                f"instrumented={image.instrumented} "
                f"coverage_complete={image.coverage_complete} detach={detach}"
            )
    return lines


__all__ = ["process_tree_to_dict", "render_process_tree_terminal"]
