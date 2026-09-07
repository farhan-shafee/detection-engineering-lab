"""Bounded data reads and repository-contained artifact references."""

import json
from pathlib import Path

import yaml

MAX_BYTES = 2_000_000


def repository(root: Path | None = None) -> Path:
    return (root or Path(__file__).resolve().parent.parent).resolve()


def safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("Artifact paths must be nonempty POSIX relative paths")
    path = Path(relative)
    if path.is_absolute() or ":" in relative or ".." in path.parts:
        raise ValueError("Artifact path escapes repository")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("Artifact path escapes repository")
    return resolved


def read_text(path: Path) -> str:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"Input exceeds {MAX_BYTES} bytes: {path.name}")
    return path.read_text(encoding="utf-8")


def unique_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate mapping key: {key}")
        result[key] = value
    return result


def load_json(path: Path):
    return json.loads(read_text(path), object_pairs_hook=unique_pairs)


class StrictLoader(yaml.SafeLoader):
    """Reject duplicate keys and aliases instead of silently accepting ambiguity."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError("YAML aliases are outside the supported rule subset")
        return super().compose_node(parent, index)


def _mapping(loader, node):
    return unique_pairs(
        [(loader.construct_object(k), loader.construct_object(v)) for k, v in node.value]
    )


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_yaml(path: Path) -> dict:
    loader = StrictLoader(read_text(path))
    try:
        result = loader.get_single_data()
    finally:
        loader.dispose()
    if not isinstance(result, dict):
        raise ValueError(f"Expected rule mapping: {path.name}")
    return result


def json_text(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
