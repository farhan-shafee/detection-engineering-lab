"""A deliberately small Sigma selection evaluator and explicit auth correlation."""

import ipaddress
import re
from datetime import datetime, timedelta
from pathlib import Path

from .io import load_yaml, safe_path

CHANNELS = {
    1: "Microsoft-Windows-Sysmon/Operational",
    4624: "Security",
    4625: "Security",
    4732: "Security",
    4698: "Security",
}
REQUIRED_FIELDS = {
    1: ("Image", "ParentImage", "CommandLine", "User"),
    4624: ("TargetUserName", "TargetDomainName", "IpAddress"),
    4625: ("TargetUserName", "TargetDomainName", "IpAddress"),
    4732: ("TargetSid", "MemberSid", "SubjectUserName"),
    4698: ("TaskName", "TaskContent", "SubjectUserName"),
}


def event_time(event: dict) -> datetime:
    value = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("Event timestamp requires timezone")
    return value


def event_valid(event) -> bool:
    if not isinstance(event, dict) or type(event.get("EventID")) is not int:
        return False
    event_id = event["EventID"]
    if event_id not in CHANNELS or event.get("Channel") != CHANNELS[event_id]:
        return False
    fields = ("timestamp", "record_id", "Computer") + REQUIRED_FIELDS[event_id]
    if any(
        not isinstance(event.get(field), str)
        or not event[field].strip()
        or len(event[field]) > 32768
        for field in fields
    ):
        return False
    try:
        event_time(event)
        if event_id in (4624, 4625):
            ipaddress.ip_address(event["IpAddress"])
    except (ValueError, TypeError, OverflowError):
        return False
    return True


def validate_rule_subset(rule: dict) -> None:
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("Sigma detection must be a mapping")
    condition = detection.get("condition")
    if condition not in ("selection", "selection and not filter"):
        raise ValueError("Unsupported Sigma condition; fail closed")
    expected_keys = {"selection", "condition"}
    if condition == "selection and not filter":
        expected_keys.add("filter")
    if set(detection) != expected_keys:
        raise ValueError("Unsupported or unused Sigma selection")
    for selector in expected_keys - {"condition"}:
        mapping = detection[selector]
        if not isinstance(mapping, dict) or not mapping:
            raise ValueError("Sigma selection must be a nonempty mapping")
        for key, value in mapping.items():
            if not isinstance(key, str):
                raise ValueError("Sigma field must be a string")
            parts = key.split("|")
            if len(parts) > 2 or (
                len(parts) == 2 and parts[1] not in {"endswith", "contains", "re"}
            ):
                raise ValueError("Unsupported Sigma modifier")
            values = value if isinstance(value, list) else [value]
            if not values or any(type(v) not in (str, int) for v in values):
                raise ValueError("Sigma values must be nonempty string/integer scalars or lists")
            if parts[-1] != "re" and any(
                isinstance(v, str) and ("*" in v or "?" in v) for v in values
            ):
                raise ValueError("Sigma wildcards are outside the supported subset")
            if parts[-1] == "re":
                for pattern in values:
                    re.compile(pattern)


def _selection(selection: dict, event: dict) -> bool:
    for key, expected in selection.items():
        field, _, modifier = key.partition("|")
        actual = event.get(field)
        values = expected if isinstance(expected, list) else [expected]

        def compare(value, actual=actual, modifier=modifier):
            if isinstance(actual, str) and isinstance(value, str):
                left, right = actual.casefold(), value.casefold()
                if modifier == "endswith":
                    return left.endswith(right)
                if modifier == "contains":
                    return right in left
                if modifier == "re":
                    return re.search(value, actual) is not None
                return left == right
            return not modifier and type(actual) is type(value) and actual == value

        if not any(compare(value) for value in values):
            return False
    return True


def sigma_matches(rule: dict, event: dict) -> bool:
    validate_rule_subset(rule)
    detection = rule["detection"]
    return _selection(detection["selection"], event) and not (
        detection["condition"] == "selection and not filter"
        and _selection(detection["filter"], event)
    )


def load_authentication_components(detection: dict, root: Path) -> dict[int, dict]:
    """Assign each actual Sigma selector an unambiguous failure or success role."""
    if len(detection["sigma"]) != 2 or set(detection["event_ids"]) != {4624, 4625}:
        raise ValueError("Auth correlation requires two Sigma components for 4625 and 4624")
    components = {}
    for relative in detection["sigma"]:
        rule = load_yaml(safe_path(root, relative))
        validate_rule_subset(rule)
        selector = rule["detection"]["selection"]
        event_id = selector.get("EventID")
        if (
            rule["detection"]["condition"] != "selection"
            or type(event_id) is not int
            or event_id not in {4624, 4625}
            or selector.get("Channel") != "Security"
            or event_id in components
        ):
            raise ValueError("Auth components require unique 4625/4624 Security selections")
        components[event_id] = rule
    return components


def _authentication_key(event: dict) -> tuple[str, ...]:
    return tuple(
        event[field].casefold()
        for field in ("Computer", "TargetUserName", "TargetDomainName", "IpAddress")
    )


def match_events(detection: dict, events: list, root: Path) -> list[list[dict]]:
    """Return contributing records. A match alone is never an incident decision."""
    valid = []
    seen = set()
    for event in events:
        if not event_valid(event) or event["EventID"] not in detection["event_ids"]:
            continue
        if event["Channel"] != detection["logsource"]["channel"]:
            continue
        identity = (event["Computer"], event["Channel"], event["record_id"])
        if identity not in seen:
            seen.add(identity)
            valid.append(event)
    valid.sort(key=lambda event: (event_time(event), event["record_id"]))
    if detection["id"] == "DET-003":
        components = load_authentication_components(detection, root)
        selected = [event for event in valid if sigma_matches(components[event["EventID"]], event)]
        success_times = {
            (_authentication_key(event), event_time(event))
            for event in selected
            if event["EventID"] == 4624
        }
        groups = {}
        matches = []
        for event in selected:
            key = _authentication_key(event)
            timestamp = event_time(event)
            # Equal timestamps establish no ordering around a successful login.
            # Exclude tied failures from both episodes regardless of record-ID sort order.
            if event["EventID"] == 4625 and (key, timestamp) in success_times:
                continue
            previous = groups.setdefault(key, [])
            lower = timestamp - timedelta(seconds=300)
            previous[:] = [item for item in previous if event_time(item) >= lower]
            if event["EventID"] == 4625:
                previous.append(event)
            elif event["EventID"] == 4624:
                failures = [item for item in previous if event_time(item) < timestamp]
                if len(failures) >= 5:
                    matches.append(failures + [event])
                previous.clear()  # New successful login starts a new correlation episode.
        return matches
    if len(detection["sigma"]) != 1:
        raise ValueError("Single-event detections require one Sigma rule")
    rule = load_yaml(safe_path(root, detection["sigma"][0]))
    return [[event] for event in valid if sigma_matches(rule, event)]
