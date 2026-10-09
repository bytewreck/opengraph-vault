"""Vault schema loading and OpenHound model registration."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from openhound.core.app import OpenHound
from openhound.core.asset import EdgeDef, NodeDef

from .graph import VaultNodeProperties


@lru_cache(maxsize=1)
def load_vault_schema() -> dict[str, Any]:
    """Load the packaged schema, falling back to the source checkout."""
    packaged_schema = files("openhound_vault").joinpath("schema.json")
    if packaged_schema.is_file():
        with packaged_schema.open("r", encoding="utf-8") as schema_file:
            return json.load(schema_file)

    repository_schema = Path(__file__).resolve().parents[2] / "schema.json"
    with repository_schema.open("r", encoding="utf-8") as schema_file:
        return json.load(schema_file)


@lru_cache(maxsize=1)
def relationship_traversability() -> dict[str, bool]:
    """Return the authoritative traversability for every Vault edge kind."""
    return {
        relationship["name"]: bool(relationship.get("is_traversable", False))
        for relationship in load_vault_schema()["relationship_kinds"]
    }


def register_vault_schema(app: OpenHound) -> None:
    """Register every Vault node and relationship kind with OpenHound."""
    schema = load_vault_schema()

    for node in schema["node_kinds"]:
        app.nodes.append(
            NodeDef(
                kind=node["name"],
                description=node["description"],
                icon=node.get("icon") or "cube",
                color=node.get("color") or "#6C757D",
                properties=VaultNodeProperties,
            )
        )

    for relationship in schema["relationship_kinds"]:
        app.edges.append(
            EdgeDef(
                # Vault relationships are polymorphic. Their concrete endpoint
                # kinds are retained on emitted nodes rather than duplicated in
                # a second endpoint matrix.
                start="Vault",
                end="Vault",
                kind=relationship["name"],
                description=relationship["description"],
                traversable=bool(relationship.get("is_traversable", False)),
            )
        )

