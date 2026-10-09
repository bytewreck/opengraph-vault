# Collector Behavior

## Invocation

The OpenHound source requires a Vault token and supports an optional Enterprise namespace.

```powershell
$env:VAULT_ADDR = "https://vault.example"
$env:VAULT_TOKEN = "..."
$env:VAULT_NAMESPACE = "admin/team-a"
openhound collect vault .\data\vault
openhound convert vault .\data\vault\vault .\data\opengraph
```

The equivalent DLT settings can be placed in `.dlt/secrets.toml`:

```toml
[sources.vault.credentials]
address = "https://vault.example"
token = "..."
namespace = "admin/team-a"
```

The collector does not attempt authentication workflows. It uses the supplied token for authenticated Vault API requests. The token is used only by `collect`; `convert` reads the persisted DLT snapshot without contacting Vault.

## Collection Phases

The current pipeline is ordered so later edge derivation can use all collected lookup tables.

1. Collect server health and leader metadata.
2. Create namespace and subsystem store nodes.
3. Discover auth mounts and method-specific configuration.
4. Collect auth users, groups, roles, CRLs, and other durable child objects.
5. Discover secrets-engine mounts, retaining unsupported mounts generically.
6. Collect supported engine configuration and child resources.
7. Collect ACL policies and parse HCL path blocks.
8. Collect entities, groups, aliases, SCIM, OIDC, MFA, and managed keys.
9. Compute structural, identity, policy, and access edges.
10. Resolve templates and identity-effective relationships.
11. Canonicalize names and properties, merge duplicate evidence, and prune redundant edges.
12. Sanitize graph properties and emit typed `VaultGraphAsset` records to the DLT snapshot.

## Conversion Phase

OpenHound reads the persisted `vault_graph` JSONL resource and converts each record through the native graph model:

1. Node records become OpenHound `Node` objects with stable IDs, Vault kinds, required environment properties, and dynamic Vault properties.
2. Relationship records become OpenHound `Edge` objects with ID-matched endpoints, evidence properties, and schema-derived traversability.
3. OpenHound appends the `Vault` source kind, batches graph objects, and writes standard OpenGraph JSON output.

Vault discovery and policy evaluation happen during `collect`; `convert` is deterministic and offline.

## Stable IDs

Node IDs use a prefix derived from the SHA-256 hash of the Vault address followed by the resource family and durable Vault identifier:

```text
vault_<instance-hash>_entity_<entity-id>
vault_<instance-hash>_auth_approle_role_<accessor>_<role-name>
```

This avoids collisions between different collected Vault addresses while keeping IDs deterministic for the same endpoint and object.

## Vault API Requests

The client normalizes Vault response envelopes and supports `GET`, `LIST`, `POST`, and `DELETE` operations needed for collection. Collection invokes only read/list-style resource discovery and configuration lookup operations. It does not request dynamic credentials, decrypt ciphertext, sign data, generate OTPs, rotate credentials, or mutate Vault configuration.

Some Vault endpoints use `GET ?list=true` rather than the non-standard `LIST` method. The client handles the endpoint form implemented by the collector.

## Partial Collection

VaultHound is permission-sensitive. A missing child can mean:

- The object does not exist.
- The collector token lacks `read` or `list` permission.
- The endpoint is unavailable in the running Vault edition or version.
- The backend plugin does not support that endpoint.
- Collection failed or returned incomplete data.

The collector avoids asserting absence when collection completeness is unknown. Features such as database connection viability track whether the relevant collection completed before deciding between no edge and `Vault_PotentialAccess`.

Collection logs should be retained with output when completeness matters to an assessment.

## Policy Parsing

The HCL parser extracts:

- Path expressions
- Capability lists
- `allowed_parameters`
- `denied_parameters`
- `required_parameters`
- Template references

Capabilities are normalized and filtered per endpoint operation. `deny` rules override grants selected by Vault path precedence.

### Wildcards

- `+` matches one path segment.
- A trailing `*` is a prefix glob.
- Exact paths do not imply access to children.
- A directory list permission does not imply secret read permission.

The collector compares policy paths against resource-specific API surfaces. KV v2 `data`, `metadata`, `delete`, `undelete`, `destroy`, `subkeys`, and `config` paths are not treated as interchangeable.

### Templates

Vault identity expressions are preserved in `Matched Policy Paths` and rendered into `Matched Paths`. Resolution supports entity attributes, alias attributes, and group references represented by the collected identity data.

The identity object referenced by the template is the source of the effective edge. A group that merely contributed the policy remains provenance rather than becoming the principal.

## Target Selection

### Observed Exact Targets

An exact path targets the matching observed object.

### Observed Glob Expansion

For supported backends, globs are expanded over every observed compatible child. This avoids relying on traversable containment from a mount for narrowly scoped operations.

### Synthetic Exact Targets

If a policy names a missing exact object that could be created or accessed, the collector may create a synthetic node. Synthetic objects are marked and excluded from ordinary containment. Attack-outcome edges to synthetic targets are converted to potential access.

### Mount and Store Anchors

Mounts and stores are used for operations that are genuinely collection-wide, configuration-scoped, or runtime-selected. Generic object edges record the object type and scope. Traversable object-level operations should target concrete children whenever collection makes that possible.

## Edge Canonicalization and Merging

Backend-specific internal edges are canonicalized into exported families. During merge:

- Sources, destinations, and canonical edge kind form the relationship identity.
- Array evidence is deduplicated.
- Boolean evidence uses explicit merge rules.
- Operation-specific capabilities are retained.
- Paths and provenance from multiple matching rules accumulate.
- Human-readable target summaries replace opaque internal grant evidence.

This is why one exported `Vault_ManageObject` edge can represent several compatible management endpoints while retaining separate operations.

## Pruning

Before snapshot emission the collector removes:

- Namespace containment to non-top-level subsystem objects.
- Synthetic containment edges.
- Redundant mount-level object-summary edges when concrete children are available.
- Unsupported-engine internal resource data.
- Duplicate edges after property merging.

## Output Safety and Validation

Nested API values are converted to JSON strings, null values are removed, and node properties are normalized before snapshot emission. OpenHound then writes graph files containing nodes and edges registered from `schema.json`.

Recommended checks:

```powershell
python -m compileall -q src
python -m pytest -q
python Documentation/tools/generate_schema_reference.py --check
python -c "import json; json.load(open('schema.json', encoding='utf-8'))"
```

The test suite focuses on security-sensitive path decisions such as synthetic targets, RoleID availability, cloud-key compatibility, MFA prerequisites, database connection viability, LDAP checkout availability, SCIM ownership, and trust replacement.
