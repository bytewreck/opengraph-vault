"""Native OpenHound graph models for normalized Vault records."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any, Literal

from openhound.core.asset import BaseAsset
from openhound.core.models.entries import (
    Edge,
    EdgePath,
    EdgeProperties,
    Node,
    NodeProperties,
)
from pydantic import Field, computed_field, model_validator


class VaultNodeProperties(NodeProperties):
    """OpenHound-required fields plus the Vault model's dynamic properties."""


class VaultEdgeProperties(EdgeProperties):
    """OpenHound edge metadata plus endpoint-specific Vault evidence."""


class VaultNode(Node):
    """Native OpenHound node using the collector's stable Vault identifier."""

    source_id: str = Field(exclude=True)

    @classmethod
    def guid(cls, name: str, node_type: str, *args: str) -> str:
        value = ".".join((name, str(node_type), *map(str, args)))
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"vault:{value}"))

    @computed_field
    @property
    def id(self) -> str:
        return self.source_id


class VaultGraphAsset(BaseAsset):
    """A typed DLT row that converts to one native OpenHound graph object."""

    record_type: Literal["node", "edge"]
    environment_id: str
    node_id: str | None = None
    kinds: list[str] = Field(default_factory=list)
    start_id: str | None = None
    end_id: str | None = None
    relationship_kind: str | None = None
    traversable: bool = False
    properties: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_record(self) -> "VaultGraphAsset":
        if self.record_type == "node" and (not self.node_id or not self.kinds):
            raise ValueError("node records require node_id and at least one kind")
        if self.record_type == "edge" and not all(
            (self.start_id, self.end_id, self.relationship_kind)
        ):
            raise ValueError(
                "edge records require start_id, end_id, and relationship_kind"
            )
        return self

    @property
    def as_node(self) -> VaultNode | None:
        if self.record_type != "node":
            return None

        raw_properties = dict(self.properties)
        name = str(
            raw_properties.get("name")
            or raw_properties.get("displayname")
            or raw_properties.get("display_name")
            or self.node_id
        )
        raw_properties.setdefault("name", name)
        raw_properties.setdefault(
            "displayname",
            str(raw_properties.get("display_name") or name),
        )
        raw_properties.setdefault("environmentid", self.environment_id)

        return VaultNode(
            source_id=str(self.node_id),
            kinds=list(self.kinds),
            properties=VaultNodeProperties.model_validate(raw_properties),
        )

    @property
    def edges(self) -> Iterable[Edge]:
        if self.record_type != "edge":
            return ()

        edge_properties = dict(self.properties)
        edge_properties["traversable"] = self.traversable
        return (
            Edge(
                kind=str(self.relationship_kind),
                start=EdgePath(match_by="id", value=str(self.start_id)),
                end=EdgePath(match_by="id", value=str(self.end_id)),
                properties=VaultEdgeProperties.model_validate(edge_properties),
            ),
        )

