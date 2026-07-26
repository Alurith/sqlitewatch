import pytest

from sqlitewatch.process_tree import (
    DuplicateProcessImage,
    ProcessTreeLimitExceeded,
    ProcessTreeRegistry,
    UnknownProcessParent,
    aggregate_instrumentation_status,
)


def test_registry_tracks_parent_depth_exec_images_and_start_tokens():
    registry = ProcessTreeRegistry(start_token_reader=lambda pid: f"start-{pid}")
    root = registry.admit_root(10, origin="exec", identifier="python")
    child = registry.admit_child(11, 10, origin="fork", identifier=None)
    grandchild = registry.admit_child(12, 11, origin="spawn", identifier="worker")
    registry.mark_instrumented(root.instance)
    registry.mark_status(root.instance, "NOT_DETECTED")
    registry.mark_instrumented(child.instance)
    registry.mark_status(child.instance, "NOT_DETECTED")
    registry.mark_detached(child.instance, "process-replaced")
    child_exec = registry.admit_child(11, 11, origin="exec", identifier="python3")
    registry.mark_instrumented(child_exec.instance)
    registry.mark_status(child_exec.instance, "ACTIVE")
    registry.mark_instrumented(grandchild.instance)
    registry.mark_status(grandchild.instance, "NOT_DETECTED")

    frozen = registry.freeze()
    assert [(process.pid, process.parent_pid, process.depth) for process in frozen.processes] == [
        (10, None, 0), (11, 10, 1), (12, 11, 2),
    ]
    assert [image.instance for image in frozen.processes[1].images] == [
        "p11-i1", "p11-i2",
    ]
    assert registry.start_token(12) == "start-12"
    assert frozen.process_count == 3
    assert frozen.image_count == 4
    assert aggregate_instrumentation_status(frozen) == "ACTIVE"


def test_registry_rejects_unknown_ancestry_and_non_exec_duplicate_pid():
    registry = ProcessTreeRegistry()
    root = registry.admit_root(10)
    registry.mark_instrumented(root.instance)
    with pytest.raises(UnknownProcessParent):
        registry.admit_child(12, 99, origin="spawn")
    with pytest.raises(DuplicateProcessImage):
        registry.admit_child(10, 10, origin="fork")


def test_exec_rejects_pid_reuse_with_a_different_start_token():
    registry = ProcessTreeRegistry()
    root = registry.admit_root(10, start_token="before")
    registry.mark_instrumented(root.instance)
    with pytest.raises(DuplicateProcessImage, match="start token changed"):
        registry.admit_child(
            10, 10, origin="exec", start_token="after"
        )
    assert registry.image_count == 1


def test_process_and_image_caps_are_bounded_and_mark_coverage_partial():
    process_limited = ProcessTreeRegistry(
        max_followed_processes=1, max_process_images=3
    )
    root = process_limited.admit_root(10)
    process_limited.mark_instrumented(root.instance)
    with pytest.raises(ProcessTreeLimitExceeded, match="max_followed_processes"):
        process_limited.admit_child(11, 10, origin="spawn")
    frozen = process_limited.freeze()
    assert not frozen.complete
    assert frozen.omitted_images == 1
    assert aggregate_instrumentation_status(frozen) == "PARTIAL"

    image_limited = ProcessTreeRegistry(
        max_followed_processes=2, max_process_images=1
    )
    root = image_limited.admit_root(20)
    image_limited.mark_instrumented(root.instance)
    with pytest.raises(ProcessTreeLimitExceeded, match="max_process_images"):
        image_limited.admit_child(20, 20, origin="exec")
    assert image_limited.image_count == 1
    assert image_limited.omitted_images == 1


def test_status_reduction_matches_process_tree_contract():
    registry = ProcessTreeRegistry()
    root = registry.admit_root(1)
    child = registry.admit_child(2, 1, origin="spawn")
    for admission in (root, child):
        registry.mark_instrumented(admission.instance)
    registry.mark_status(root.instance, "ACTIVE")
    registry.mark_status(child.instance, "DETECTED_UNSUPPORTED")
    assert aggregate_instrumentation_status(registry.freeze()) == "PARTIAL"
    assert aggregate_instrumentation_status(
        registry.freeze(), fatal_failure=True
    ) == "FAILED"


def test_coverage_loss_is_visible_in_frozen_image():
    registry = ProcessTreeRegistry()
    root = registry.admit_root(1)
    registry.mark_coverage_loss(root.instance, "ready timeout")
    frozen = registry.freeze()
    assert not frozen.complete
    assert frozen.processes[0].images[0].instrumentation_status == "PARTIAL"
    assert frozen.processes[0].images[0].detach_reason == "ready timeout"
