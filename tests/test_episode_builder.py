
from datetime import datetime, timedelta, timezone

import pytest

from src.episode_builder import EpisodeBuilder
from src.telemetry import ProcessCreation, NetworkConnection


BASE = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)


def make_process(guid, parent_guid, minute=0, machine="host-01"):
    return ProcessCreation(
        timestamp=BASE + timedelta(minutes=minute),
        machine_name=machine,
        process_guid=guid,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c echo test",
        parent_process_guid=parent_guid,
        parent_image="C:\\Windows\\explorer.exe",
    )


def make_connection(guid, minute=0, machine="host-01"):
    return NetworkConnection(
        timestamp=BASE + timedelta(minutes=minute),
        machine_name=machine,
        process_guid=guid,
        destination_ip="203.0.113.10",
        destination_port=443,
        protocol="tcp",
    )


@pytest.fixture
def builder():
    return EpisodeBuilder(timedelta(minutes=5))


@pytest.fixture
def root():
    return make_process("root-guid", "parent-guid")


def test_includes_child_process(builder, root):
    child = make_process("child-guid", "root-guid", minute=1)

    episode = builder.build(
        target=root,
        processes=[root, child],
        connections=[],
        decision_time=BASE + timedelta(minutes=3),
    )

    assert len(episode.related_processes) == 1
    assert episode.related_processes[0].process_guid == "child-guid"


def test_excludes_future_events(builder, root):
    future = make_connection("root-guid", minute=10)

    episode = builder.build(
        target=root,
        processes=[root],
        connections=[future],
        decision_time=BASE + timedelta(minutes=3),
    )

    assert episode.network_connections == []


def test_excludes_other_machines(builder, root):
    unrelated = make_process(
        "child-guid",
        "root-guid",
        minute=1,
        machine="host-02",
    )

    episode = builder.build(
        target=root,
        processes=[root, unrelated],
        connections=[],
        decision_time=BASE + timedelta(minutes=3),
    )

    assert episode.related_processes == []


def test_includes_child_network_connections(builder, root):
    child = make_process("child-guid", "root-guid", minute=1)
    connection = make_connection("child-guid", minute=2)

    episode = builder.build(
        target=root,
        processes=[root, child],
        connections=[connection],
        decision_time=BASE + timedelta(minutes=3),
    )

    assert len(episode.network_connections) == 1


def test_rejects_decision_before_process_creation(builder, root):
    with pytest.raises(ValueError):
        builder.build(
            target=root,
            processes=[root],
            connections=[],
            decision_time=BASE - timedelta(minutes=1),
        )


def test_rejects_naive_decision_timestamp(builder, root):
    with pytest.raises(ValueError):
        builder.build(
            target=root,
            processes=[root],
            connections=[],
            decision_time=datetime(2026, 1, 1, 10, 3),
        )
