"""Tests for the native OpenHound adapter."""

import json
from pathlib import Path
import sys
from types import SimpleNamespace

import dlt
import pytest

pytest.importorskip("openhound")

sys.path.insert(0, str(Path(__file__).parent / "src"))

from openhound_vault.graph import VaultGraphAsset
from openhound_vault.main import app
from openhound_vault.schema import load_vault_schema
from openhound_vault.source import (
    VaultCredentials,
    iter_collector_records,
    resolve_vault_credentials,
    source as vault_source,
)
from openhound.core.collect import Collector
from openhound.core.convert import Converter
from openhound.core.progress import Progress


def test_registers_the_complete_vault_schema():
    schema = load_vault_schema()

    assert {definition.kind for definition in app.nodes} == {
        node["name"] for node in schema["node_kinds"]
    }
    assert {definition.kind for definition in app.edges} == {
        edge["name"] for edge in schema["relationship_kinds"]
    }


def test_node_conversion_adds_required_openhound_properties():
    asset = VaultGraphAsset(
        record_type="node",
        environment_id="vault_environment",
        node_id="vault_node",
        kinds=["Vault_Entity"],
        properties={"name": "alice", "Entity ID": "entity-id"},
    )

    node = asset.as_node

    assert node is not None
    assert node.id == "vault_node"
    assert node.properties.name == "alice"
    assert node.properties.displayname == "alice"
    assert node.properties.environmentid == "vault_environment"
    assert node.properties.model_extra["Entity ID"] == "entity-id"


def test_edge_conversion_uses_native_paths_and_traversability():
    asset = VaultGraphAsset(
        record_type="edge",
        environment_id="vault_environment",
        start_id="source",
        end_id="target",
        relationship_kind="Vault_ControlObject",
        traversable=True,
        properties={"operations": ["update"]},
    )

    edge = next(iter(asset.edges))

    assert edge.start.match_by == "id"
    assert edge.start.value == "source"
    assert edge.end.value == "target"
    assert edge.properties.traversable is True
    assert edge.properties.model_extra["operations"] == ["update"]


def test_snapshot_adapter_deduplicates_relationships_like_legacy_output():
    node = SimpleNamespace(
        id="node",
        kinds=["Vault_Entity"],
        properties={"name": "alice"},
    )
    edge = SimpleNamespace(
        source="source",
        target="target",
        kind="Vault_MapsTo",
        properties={},
    )
    collector = SimpleNamespace(
        nodes=[node],
        edges=[edge, edge],
        _id=lambda value: f"environment-{value}",
    )

    records = list(iter_collector_records(collector))

    assert [record["record_type"] for record in records] == ["node", "edge"]


def test_standard_vault_environment_variables_are_supported(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example")
    monkeypatch.setenv("VAULT_TOKEN", "standard-vault-token")
    monkeypatch.setenv("VAULT_NAMESPACE", "engineering")

    resolved = resolve_vault_credentials(VaultCredentials())

    assert resolved.address == "https://vault.example"
    assert resolved.token == "standard-vault-token"
    assert resolved.namespace == "engineering"


def test_dlt_credentials_take_precedence_over_standard_environment(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "https://environment.example")
    monkeypatch.setenv("VAULT_TOKEN", "environment-token")
    monkeypatch.setenv("VAULT_NAMESPACE", "environment")

    resolved = resolve_vault_credentials(
        VaultCredentials(
            address="https://configured.example",
            token="configured-token",
            namespace="configured",
        )
    )

    assert resolved.address == "https://configured.example"
    assert resolved.token == "configured-token"
    assert resolved.namespace == "configured"


def test_missing_vault_token_lists_supported_configuration(monkeypatch):
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    with pytest.raises(ValueError, match="SOURCES__VAULT__CREDENTIALS__TOKEN"):
        resolve_vault_credentials(VaultCredentials())


def test_openhound_collection_and_conversion_round_trip(tmp_path):
    records = [
        VaultGraphAsset(
            record_type="node",
            environment_id="vault_server",
            node_id="vault_server",
            kinds=["Vault_Server"],
            properties={"name": "test-vault"},
        ).model_dump(),
        VaultGraphAsset(
            record_type="node",
            environment_id="vault_server",
            node_id="vault_namespace",
            kinds=["Vault_Namespace"],
            properties={"name": "root"},
        ).model_dump(),
        VaultGraphAsset(
            record_type="edge",
            environment_id="vault_server",
            start_id="vault_server",
            end_id="vault_namespace",
            relationship_kind="Vault_Contains",
            traversable=True,
            properties={},
        ).model_dump(),
    ]

    @dlt.resource(name="vault_graph", columns=VaultGraphAsset)
    def fixture_graph():
        yield from records

    @dlt.source(name="vault_fixture", max_table_nesting=0)
    def fixture_source():
        return (fixture_graph(),)

    raw_path = tmp_path / "raw"
    graph_path = tmp_path / "graph"
    collector = Collector(
        name="vault_fixture",
        output_path=raw_path,
        progress=Progress.log,
    )
    collector.run(fixture_source())

    converter = Converter(
        name="vault_fixture",
        input_path=raw_path / "vault_fixture",
        output_path=graph_path,
        lookup=None,
        source_kind="Vault",
        progress=Progress.log,
    )
    converter.run(
        vault_source(
            credentials=VaultCredentials(
                address="https://vault.example",
                token="not-used-during-conversion",
            )
        ),
        graph_resources=[VaultGraphAsset],
        extra_context={},
    )

    assert list(raw_path.rglob("*.jsonl.gz"))
    output_files = list(graph_path.glob("*.json"))
    assert len(output_files) == 1

    output = json.loads(output_files[0].read_text(encoding="utf-8"))
    assert len(output["graph"]["nodes"]) == 2
    assert output["graph"]["nodes"][0]["kinds"] == ["Vault_Server", "Vault"]
    assert output["graph"]["edges"][0]["properties"]["traversable"] is True
