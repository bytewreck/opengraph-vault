# VaultHound Model Documentation

VaultHound translates HashiCorp Vault configuration and ACL policy into a BloodHound OpenGraph model. The documentation follows the same hierarchy as the graph: shared semantics live in the model guide, while each namespace-local store has its own subsystem guide.

## Start Here

| Document | Purpose |
| --- | --- |
| [Graph Model](MODEL.md) | Model goals, hierarchy, the five stores, base node and edge types, path resolution, properties, and traversability. |
| [Identity Store](stores/IDENTITY.md) | Entities, aliases, groups, outbound OIDC, MFA, SCIM, and identity attack paths. |
| [Policy Store](stores/POLICIES.md) | ACL collection, assignment, path resolution, administration, and policy-acquisition paths. |
| [Auth Store](stores/AUTH.md) | Supported authentication methods, their child objects, policy grants, topology, and per-method attack paths. |
| [Mount Store](stores/MOUNTS.md) | Supported secrets engines, their resources, topology, and per-engine attack paths. |
| [Managed Keys Store](stores/MANAGED_KEYS.md) | Enterprise managed keys, cryptographic references, and attack-path boundaries. |

## Technical Appendices

| Document | Purpose |
| --- | --- |
| [Collection and Output](COLLECTION.md) | Collector phases, API behavior, output format, and validation workflow. |
| [Generated Schema Reference](SCHEMA.md) | Complete node and relationship registry generated from `schema.json` and collector endpoint mappings. |

`SCHEMA.md` is generated and should not be edited by hand:

```powershell
python Documentation/tools/generate_schema_reference.py
python Documentation/tools/generate_schema_reference.py --check
```

## Source Of Truth

The implementation is authoritative when documentation and code differ:

1. `schema.json` defines exported node kinds, relationship kinds, icons, descriptions, and traversability.
2. `vault_collector.py` defines collection behavior, Vault endpoint mappings, policy resolution, and properties.
3. `test_access_path_traversability.py` captures focused behavioral and attack-path expectations.
4. `Documentation/SCHEMA.md` is the generated reference for the current exported schema.

VaultHound models authority and security outcomes without collecting KV plaintext or invoking credential-generation endpoints. Treat collector output as sensitive because configuration and graph relationships can still reveal credentials, trust configuration, and attack paths.
