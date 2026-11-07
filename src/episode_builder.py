
from datetime import datetime, timedelta, timezone
from typing import Sequence

from src.telemetry import (
    InvestigationEpisode,
    NetworkConnection,
    ProcessCreation,
)


class EpisodeBuilder:
    """Builds point-in-time investigation episodes from Sysmon events."""

    def __init__(self, observation_window: timedelta):
        if observation_window <= timedelta(0):
            raise ValueError("Observation window must be positive")

        self.observation_window = observation_window

    @staticmethod
    def _validate_timestamp(timestamp: datetime) -> None:
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("All timestamps must be timezone-aware")

    def build(
        self,
        target: ProcessCreation,
        processes: Sequence[ProcessCreation],
        connections: Sequence[NetworkConnection],
        decision_time: datetime,
    ) -> InvestigationEpisode:
        """
        Construct an episode using only telemetry observable at decision_time.

        Assumptions:
        - The target is the root process.
        - Events are timestamped in a consistent time reference.
        - The provided event history is sufficiently complete.
        - This implementation processes one bounded observation interval.
        """
        self._validate_timestamp(target.timestamp)
        self._validate_timestamp(decision_time)

        if decision_time < target.timestamp:
            raise ValueError("Decision time precedes target creation")

        cutoff = min(
            decision_time,
            target.timestamp + self.observation_window,
        )

        def visible(event):
            self._validate_timestamp(event.timestamp)
            return (
                event.machine_name == target.machine_name
                and target.timestamp <= event.timestamp <= cutoff
            )

        eligible_processes = [
            process for process in processes
            if visible(process)
        ]

        eligible_connections = [
            connection for connection in connections
            if visible(connection)
        ]

        # Build a process tree based on parent GUID relationships.
        known_guids = {target.process_guid}
        known_creation_times = {
            target.process_guid: target.timestamp
        }
        related = []
        remaining = [
            process for process in eligible_processes
            if process.process_guid != target.process_guid
        ]

        while True:
            
            newly_found = [
                process for process in remaining
                if (
                    process.parent_process_guid in known_creation_times
                    and process.timestamp >= known_creation_times[
                        process.parent_process_guid
                    ]
                )
            ]

            if not newly_found:
                break

            for process in newly_found:
                known_guids.add(process.process_guid)
                known_creation_times[process.process_guid] = process.timestamp
                related.append(process)

            found_ids = {id(process) for process in newly_found}
            remaining = [
                process for process in remaining
                if id(process) not in found_ids
            ]

        # Keep only network events belonging to the process tree.
        relevant_connections = [
            connection for connection in eligible_connections
            if connection.process_guid in known_guids
        ]

        related.sort(key=lambda event: event.timestamp)
        relevant_connections.sort(
            key=lambda event: event.timestamp
        )

        return InvestigationEpisode(
            root_process_guid=target.process_guid,
            target_process=target,
            related_processes=related,
            network_connections=relevant_connections,
        )
