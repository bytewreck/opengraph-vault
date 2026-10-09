# VaultHound

VaultHound is a HashiCorp Vault collector and OpenGraph model for BloodHound.
It can run either as the original standalone collector or as a native
[OpenHound](https://github.com/SpecterOps/OpenHound) source extension.

## OpenHound extension

The OpenHound implementation uses the complete two-stage pipeline:

1. `collect` discovers Vault resources and policy effects, validates them as a
   typed DLT snapshot, and writes the snapshot to disk.
2. `convert` turns that snapshot into native OpenHound nodes, edges, paths, and
   property models before writing OpenGraph output.

All node and relationship definitions are registered from `schema.json`.
Relationship traversability is also read from that schema, so the standalone
and OpenHound outputs use the same offensive-security semantics.

### Requirements

- Python 3.13 or newer
- OpenHound 0.4.0 or newer
- A Vault token with access to the objects that should be discovered

Install the extension into the same environment as OpenHound:

```powershell
pip install -e .
```

Configure DLT in `.dlt/secrets.toml`:

```toml
[sources.vault.credentials]
address = "https://vault.example.com:8200"
token = "hvs.example"
namespace = ""

[sources.vault]
requests_per_second = 50
```

The equivalent environment variables are
`SOURCES__VAULT__CREDENTIALS__ADDRESS`,
`SOURCES__VAULT__CREDENTIALS__TOKEN`, and
`SOURCES__VAULT__CREDENTIALS__NAMESPACE`.

The standard Vault variables are also supported, which is often the simplest
way to run the collector:

```powershell
$env:VAULT_ADDR = "https://vault.example.com:8200"
$env:VAULT_TOKEN = "hvs.example"
$env:VAULT_NAMESPACE = ""
```

DLT configuration takes precedence over the corresponding standard Vault
variable. A project-local `.dlt/secrets.toml` is discovered relative to the
directory from which `openhound` is launched.

Collect and convert the data with OpenHound:

```powershell
openhound collect vault .\data\vault
openhound convert vault .\data\vault\vault .\data\opengraph
```

DLT places the collected tables in a dataset directory named `vault`, which is
why the convert input is the nested `.\data\vault\vault` path.

The token is used only during collection and is not written into the snapshot.
Treat the collected and converted output as sensitive because it contains
Vault configuration, identities, policy paths, and access relationships.

## Standalone collector

The existing collector remains available for compatibility:

```powershell
python vault_collector.py --vault-addr https://vault.example.com:8200 --output vault_collected.json
```

Set `VAULT_TOKEN` in the environment before running it. See
[`Documentation/MODEL.md`](Documentation/MODEL.md) for the graph design and the
store-specific documentation under [`Documentation/stores`](Documentation/stores).
