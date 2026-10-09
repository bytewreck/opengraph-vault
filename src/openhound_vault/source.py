"""DLT collection source for the OpenHound Vault extension."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import dlt
from dlt.common.configuration import configspec
from dlt.common.configuration.specs import CredentialsConfiguration

import vault_collector as legacy

from .graph import VaultGraphAsset
from .main import app
from .schema import relationship_traversability

logger = logging.getLogger(__name__)


@configspec
class VaultCredentials(CredentialsConfiguration):
    """Credentials and target for a Vault collection run."""

    address: str | None = None
    token: str | None = None
    namespace: str = ""


@dataclass(frozen=True)
class ResolvedVaultCredentials:
    """Concrete credentials after applying DLT and standard Vault settings."""

    address: str
    token: str
    namespace: str


def resolve_vault_credentials(
    credentials: VaultCredentials,
) -> ResolvedVaultCredentials:
    """Resolve DLT credentials with standard Vault environment fallbacks."""
    token = credentials.token or os.environ.get("VAULT_TOKEN")
    if not token:
        raise ValueError(
            "Vault token is not configured. Set token in "
            "[sources.vault.credentials] in .dlt/secrets.toml, set "
            "SOURCES__VAULT__CREDENTIALS__TOKEN, or set VAULT_TOKEN."
        )

    return ResolvedVaultCredentials(
        address=(
            credentials.address
            or os.environ.get("VAULT_ADDR")
            or "http://127.0.0.1:8200"
        ),
        token=token,
        namespace=credentials.namespace or os.environ.get("VAULT_NAMESPACE", ""),
    )


def iter_collector_records(
    collector: legacy.VaultCollector,
) -> Iterator[dict[str, Any]]:
    """Translate a completed collector into typed, deduplicated DLT rows."""
    environment_id = collector._id("server")
    traversability = relationship_traversability()

    for node in collector.nodes:
        yield VaultGraphAsset(
            record_type="node",
            environment_id=environment_id,
            node_id=node.id,
            kinds=list(node.kinds),
            properties=legacy.sanitize_graph_properties(node.properties),
        ).model_dump()

    seen_edges: set[tuple[str, str, str]] = set()
    for edge in collector.edges:
        edge_key = (edge.source, edge.target, edge.kind)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        yield VaultGraphAsset(
            record_type="edge",
            environment_id=environment_id,
            start_id=edge.source,
            end_id=edge.target,
            relationship_kind=edge.kind,
            traversable=traversability.get(edge.kind, False),
            properties=legacy.sanitize_graph_properties(edge.properties),
        ).model_dump()


@app.resource(
    name="vault_graph",
    columns=VaultGraphAsset,
    parallelized=False,
    write_disposition="replace",
)
def vault_graph(
    credentials: VaultCredentials,
    requests_per_second: float = 50.0,
):
    """Collect and normalize one Vault environment into an OpenHound snapshot."""
    if requests_per_second <= 0:
        raise ValueError("requests_per_second must be greater than zero")

    resolved = resolve_vault_credentials(credentials)
    client = legacy.VaultClient(
        addr=resolved.address,
        token=resolved.token,
        namespace=resolved.namespace,
    )
    client._rate_delay = 1.0 / requests_per_second
    collector = legacy.VaultCollector(
        client=client,
        vault_addr=resolved.address,
        namespace_id=resolved.namespace or "root",
    )
    collector.collect_all()

    logger.info(
        "Collected normalized Vault snapshot with %d nodes and %d relationships",
        len(collector.nodes),
        len(collector.edges),
    )
    yield from iter_collector_records(collector)


@app.source(name="vault", max_table_nesting=0)
def source(
    credentials: VaultCredentials = dlt.secrets.value,
    requests_per_second: float = 50.0,
):
    """Expose the Vault snapshot as an OpenHound DLT source."""
    return (
        vault_graph(
            credentials=credentials,
            requests_per_second=requests_per_second,
        ),
    )
