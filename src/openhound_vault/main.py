"""OpenHound command registration for VaultHound."""

from __future__ import annotations

from dlt.extract.source import DltSource
from openhound.core.app import OpenHound
from openhound.core.collect import CollectContext
from openhound.core.convert import ConvertContext

from .graph import VaultGraphAsset
from .schema import register_vault_schema

app = OpenHound(
    "vault",
    source_kind="Vault",
    help="Collect HashiCorp Vault resources and convert them to OpenGraph",
)

# The normalized record is the converter resource; all concrete graph kinds are
# registered separately from schema.json below.
app.asset(description="Normalized HashiCorp Vault graph record")(VaultGraphAsset)
register_vault_schema(app)


@app.collect(help="Collect HashiCorp Vault resources into a normalized snapshot")
def collect(ctx: CollectContext) -> DltSource:
    from .source import source

    return source()


@app.convert(help="Convert a Vault snapshot to native OpenGraph nodes and edges")
def convert(ctx: ConvertContext) -> tuple[DltSource, dict]:
    from .source import source

    return source(), {}

