# VaultHound Documentation

VaultHound collects HashiCorp Vault configuration, identity, policy, authentication, and supported secrets-engine data and emits BloodHound OpenGraph JSON. This documentation describes both the exported graph schema and the collector decisions that produce it.

## Start Here

| Document | Purpose |
| --- | --- |
| [MODEL.md](MODEL.md) | Conceptual graph model, hierarchy, identities, policies, and target selection. |
| [TRAVERSABILITY.md](TRAVERSABILITY.md) | Offensive-security meaning of traversable and non-traversable relationships. |
| [SCHEMA.md](SCHEMA.md) | Generated catalog of every registered node and relationship kind. |
| [PROPERTIES.md](PROPERTIES.md) | Common node and relationship properties, value types, and provenance. |
| [COLLECTION.md](COLLECTION.md) | Collector phases, Vault API behavior, ACL parsing, and output generation. |
| [COVERAGE.md](COVERAGE.md) | Supported auth methods, secrets engines, identity features, and limitations. |
| [auth-methods/README.md](auth-methods/README.md) | Auth-method resource and policy modeling. |
| [secrets-engines/README.md](secrets-engines/README.md) | Secrets-engine resource and policy modeling. |
| [examples/attack-paths.md](examples/attack-paths.md) | Representative graph paths and how to interpret them. |
| [examples/cypher-queries.md](examples/cypher-queries.md) | Practical BloodHound Cypher queries. |

## Model Goals

VaultHound is designed to answer four questions:

1. What durable Vault objects exist, and where do they sit in the Vault hierarchy?
2. Which identities, aliases, groups, auth roles, and policies are connected?
3. Which Vault API operations does a policy authorize against concrete resources?
4. Which of those operations represent a defensible offensive-security path rather than ordinary visibility or administration?

The model deliberately distinguishes structural facts, declared ACL authority, derived effective access, proven offensive outcomes, and unresolved potential access.

## Sources of Truth

- `schema.json` is authoritative for exported node kinds, relationship kinds, display metadata, and traversability.
- `vault_collector.py` is authoritative for collection endpoints, HCL interpretation, edge targets, property derivation, canonicalization, and pruning.
- [SCHEMA.md](SCHEMA.md) is generated from `schema.json`; do not edit it manually.
- The authored guides in this directory explain intent and behavior that cannot be represented in the OpenGraph schema alone.

Regenerate and validate the schema catalog with:

```powershell
python Documentation/tools/generate_schema_reference.py
python Documentation/tools/generate_schema_reference.py --check
```

## Important Boundaries

- VaultHound does not collect KV plaintext values. It records paths and top-level key names.
- Unsupported secrets-engine mounts are retained as generic `Vault_SecretsEngine` nodes with existence and type information, but their internal resources and ACL semantics are not modeled.
- A traversable relationship is an attack-path assertion, not merely a statement that an API call is permitted.
- A synthetic node represents an exact object named by policy but not observed through Vault collection. Synthetic targets do not become unconditional attack paths.
- Public or unauthenticated Vault endpoints are generally not represented as policy-derived authority.

## Schema Versioning

The schema currently uses the `Vault_` namespace. Changes should be treated as follows:

- Adding a property is backward-compatible when consumers tolerate absent values.
- Adding a node or relationship kind requires regenerating `SCHEMA.md` and updating the relevant coverage page.
- Renaming or removing a kind is a breaking graph-query change.
- Changing traversability is a security-semantic change and requires focused tests and an entry in the project changelog.
