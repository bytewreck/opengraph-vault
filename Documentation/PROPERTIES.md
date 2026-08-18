# Property Reference

VaultHound properties provide the context that is intentionally removed from generic node and relationship names. This document describes the shared contract; subsystem pages describe specialized values.

## Property Types

BloodHound OpenGraph properties are emitted as:

- Strings
- Integers
- Floating-point values
- Booleans
- Homogeneous or mixed scalar arrays accepted by the importer

Nested Vault API objects are serialized as deterministic JSON strings. Null property values and null array members are removed before output. A missing property means unknown, unavailable, inapplicable, or not returned; it must not automatically be interpreted as false.

## Naming

Collector internals use snake_case keys while exported graph properties use human-readable labels. Acronyms are normalized deliberately, for example `Entity ID`, `Direct Group IDs`, `Use CSR Subject Alternative Names`, and `Allow IP Subject Alternative Names`.

Properties that may accumulate evidence from multiple matching policy paths are arrays. Scalar and plural spellings are not emitted together.

## Common Node Properties

| Property | Type | Meaning |
| --- | --- | --- |
| `name` | string | BloodHound primary name used for display and lookup. |
| `Path` | string | Vault API or logical resource path without presentation-only trailing slash changes. |
| `Namespace ID` | string | Namespace context in which the object was collected. |
| `Accessor` | string | Stable Vault mount accessor where returned by the API. |
| `Type` | string | Backend or resource type when a more specific label is not available. |
| `Synthetic` | boolean | The object was inferred from an exact policy path and not observed through resource collection. |
| `Local` | boolean | The mount or object is local to the cluster where Vault exposes that flag. |
| `Seal Wrap` | boolean | Vault seal wrapping is enabled for the mount. |
| `Default Lease TTL` | integer/string | Default lease TTL returned by Vault. |
| `Max Lease TTL` | integer/string | Maximum lease TTL returned by Vault. |
| `Creation Time` | string | Vault timestamp for object creation when returned. |
| `Last Update Time` | string | Vault timestamp for last modification when returned. |

Each object family also includes its durable identifiers and UI-oriented configuration. For example, identity nodes expose Entity IDs and group IDs, PKI nodes expose issuer and certificate attributes, and Transit keys expose type, version, export, derivation, and operation-support flags.

## Common Relationship Properties

### ACL Evidence

| Property | Type | Meaning |
| --- | --- | --- |
| `Capabilities` | string[] | Only Vault capabilities relevant to the exported edge operation. |
| `Matched Paths` | string[] | Concrete or rendered Vault request paths matched by the rule. |
| `Matched Policy Paths` | string[] | Original HCL policy paths before template rendering. |
| `Scopes` | string[] | Exact, collection, pattern, subtree, mount, or other target scope. |
| `Surfaces` | string[] | API surfaces such as KV data, metadata, lifecycle, PKI issuer, or Transit export. |
| `Operations` | string[] | Human-readable operations represented by the edge. |
| `Requirements` | string[] | Preconditions that must be met for the operation to succeed. |

Capabilities are endpoint-specific. A policy block containing `create`, `read`, `update`, `delete`, `list`, and `sudo` does not cause every emitted edge to carry all six values.

### Generic Object Families

| Property | Type | Meaning |
| --- | --- | --- |
| `Object Types` | string[] | Normalized target families such as Role, Static Role, Key, Connection, or KV Secret. |
| `Auth Method Types` | string[] | Auth backend families represented by a generic edge. |
| `Engine Types` | string[] | Secrets-engine families represented by a generic edge. |
| `Role Types` | string[] | Dynamic, static, OTP, CA, token, or other role distinctions. |
| `Read Targets` | string[] | Information returned by a read operation. |
| `Config Targets` | string[] | Configuration surfaces affected by a read or manage edge. |

`Object Types` is canonical. Legacy or specialized object-type labels are normalized before edge merging so one edge does not report both `Role` and `Auth Role` for the same target.

### Derivation and Uncertainty

| Property | Type | Meaning |
| --- | --- | --- |
| `Declared` | boolean | The edge directly represents declared ACL authority. |
| `Derived` | boolean | The collector inferred the relationship by composing collected facts. |
| `Effective` | boolean | The relationship represents effective identity-specific access after applicable resolution. |
| `Potential Only` | boolean | The edge is intentionally non-traversable because an outcome is unresolved. |
| `Target Observed` | boolean | The destination was returned by Vault rather than inferred. |
| `Potential Outcomes` | string[] | Security outcomes that could become available after resolving uncertainty. |
| `Resolution Status` | string[] | Reasons the collector cannot assert the full outcome. |

### Identity Templates and Provenance

| Property | Type | Meaning |
| --- | --- | --- |
| `Templated` | boolean | The policy path contains a Vault identity template. |
| `Template Entity Fields` | string[] | Entity attributes referenced by the template. |
| `Template Alias Fields` | string[] | Alias attributes referenced by the template. |
| `Template Group IDs` | string[] | Group references used by the template. |
| `Resolved Source Types` | string[] | Identity object types used to render the path. |
| `Resolved For Entity IDs` | string[] | Canonical entities for which the policy was resolved. |
| `Via Policies` | string[] | Policies contributing to the derived effective relationship. |
| `Policy Origins` | string[] | Direct, group-inherited, auth-role, or other policy provenance. |

Template-effective edges originate from the identity representation referenced by the template. Group policy inheritance remains provenance and does not automatically make the group the relationship source.

### Control and Policy Escalation

| Property | Type | Meaning |
| --- | --- | --- |
| `Control Methods` | string[] | Proven takeover mechanism, such as reset password or replace trust. |
| `Control Parameters` | string[] | Request parameters whose control makes the takeover possible. |
| `Impacts` | string[] | Resulting offensive capability. |
| `Assignable Policies` | string[] | Concrete policies that can be assigned through the operation. |
| `Policy Assignment Parameters` | string[] | Parameters that carry policy names. |
| `Via Object IDs` | string[] | Intermediate controlled objects that provide indirect-control or unresolved-assignment evidence. |

Policy-assignment properties remain contextual evidence on management, control, and potential-access edges; they do not create a direct policy-to-policy relationship.

## Subsystem Property Families

### KV

- `KV Version`
- `CAS Required`
- `Effective CAS Required`
- `Max Versions`
- `Delete Version After`
- `Metadata Read Targets`
- `Version Selection`

KV v2 edge properties distinguish engine-level and key-level CAS requirements. `Vault_KvReadSecret` and metadata edges describe only the endpoint surface actually authorized.

### Credential Engines

- `Credential Types`
- `Credential Material`
- `Generation Effects`
- `Request Surfaces`
- `Request Methods`
- `Modes`
- `Supports Custom TTL`

These values describe what Vault can return without invoking the generation endpoint during collection.

### PKI

- `Targets`
- `Issuance Protocols`
- `Issuer References`
- `Certificate Targets`
- `Certificate Format`
- `CRL Format`
- `CRL Delta Format`
- `Protocol Paths`

PKI role and issuer nodes expose human-readable Vault UI fields, certificate validity, issuer role, key usage, distribution points, and related configuration where Vault returns it.

### Transit and GCP KMS

- `Key Types`
- `Key Purposes`
- `Compatibility Status`
- `Export Types`
- `Export Outcomes`
- `Destination Keys`
- `Verification Targets`

Compatibility is enforced before traversable decrypt, sign, CMAC, HMAC, or secret export edges are emitted.

## Sensitive Properties

The output should be protected as security-sensitive data even though VaultHound avoids collecting generated credentials and KV plaintext. Configuration reads can expose values such as OIDC client secrets or external integration credentials. `Vault_ReadCredential` records the confirmed credential type, returned fields, and use without requiring the collector to exercise the credential.

Do not publish collector output to an untrusted location.
