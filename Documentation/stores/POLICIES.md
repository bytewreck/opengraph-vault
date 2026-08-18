# Policy Store

The Policy Store contains namespace-local policy documents and anchors policy-registry operations. It covers the modern ACL surface and Vault's legacy ACL path; the store also records the RGP and EGP registry paths exposed by Vault Enterprise.

```mermaid
flowchart LR
    namespace[Vault_Namespace] -->|Vault_Contains| store[Vault_Store: POLICIES]
    store -->|Vault_Contains| policy[Vault_Policy]
    identity[Entity, group, or auth object] -->|Vault_LinksPolicy| policy
    policy -->|Declared access edge| target[Concrete Vault object]
```

## Nodes

| Node | Description |
| --- | --- |
| `Vault_Store` | Namespace-local policy registry with paths for `sys/policy`, `sys/policies/acl`, `sys/policies/rgp`, and `sys/policies/egp`. |
| `Vault_Policy` | Collected policy document with name, namespace, raw rules, parsed path summary, capabilities, and policy metadata. |

ACL policy collection and endpoint-aware ACL resolution are the first-class behavior. Registry paths retained on the store do not imply that every Enterprise policy type is parsed with ACL semantics.

## Containment And Assignment

```mermaid
flowchart LR
    store[Policy Store] -->|Vault_Contains| policy[Vault_Policy]
    entity[Vault_Entity] -->|Vault_LinksPolicy| policy
    group[Vault_Group] -->|Vault_LinksPolicy| policy
    role[Auth role, user, or group] -->|Vault_LinksPolicy| policy
```

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | --- | --- |
| `Vault_Contains` | Policy Store | Policy | Yes | Observed policy belongs to this namespace registry. |
| `Vault_LinksPolicy` | Identity or auth configuration object | Policy | Yes | Object directly receives or grants the policy. |

`Policy Link Types` distinguishes direct entity assignment, group inheritance, auth-role grant, auth-user grant, auth-group grant, and backend defaults. The edge describes configured policy acquisition; it is not merely a textual reference.

## Policy Administration

```mermaid
flowchart LR
    admin[Vault_Policy] -->|Vault_ListObjects| store[Policy Store]
    admin -->|Vault_CreateObject| store
    admin -->|Vault_ReadObject| target[Vault_Policy]
    admin -->|Vault_ManageObject| target
```

| Edge | Destination | Meaning |
| --- | --- | --- |
| `Vault_ListObjects` | Policy Store | List policies through modern or legacy collection endpoints. |
| `Vault_CreateObject` | Policy Store or synthetic policy | Create a policy, preserving policy type and API surface in properties. |
| `Vault_ReadObject` | Concrete policy | Read policy rules. |
| `Vault_ManageObject` | Concrete policy | Update, patch, or delete policy rules. |
| `Vault_ObtainPolicy` | Concrete policy | Derived attack path showing that another controlled object can be assigned this policy. |

Ordinary policy management is non-traversable. Merely being able to modify a policy does not prove that the caller or an attacker-controlled identity receives it. `Vault_ObtainPolicy` requires both a proven takeover path and a proven policy-assignment parameter on the same controlled object.

### Attack Paths

Policies normally serve as the authority-bearing middle of a path:

```text
Vault_Entity or Vault_Group
  -> Vault_LinksPolicy
Vault_Policy
  -> Traversable security-outcome edge
Concrete target
```

Policy administration becomes an escalation path only when a controlled object can actually receive a policy:

```text
Vault_Policy A
  -> Vault_ControlObject
Identity or auth object
  -> Vault_ObtainPolicy
Vault_Policy B
```

The direct `Vault_ObtainPolicy` edge records the via object, assignable policy, assignment parameter, and control method. A standalone `Vault_ManageObject` edge to Policy B is intentionally not traversable.

## ACL Path Resolution

For each path block, VaultHound:

1. Parses and normalizes the capability set.
2. Preserves the original HCL path as `Matched Policy Paths`.
3. Renders identity templates when a concrete identity context is available.
4. Compares the resulting path with supported endpoint surfaces.
5. Emits only operation-relevant capabilities on the resulting edge.
6. Applies deny precedence and endpoint-specific sudo requirements.

```mermaid
flowchart LR
    document[Vault_Policy] --> block[HCL path block]
    block --> matcher[Exact, +, *, or template matcher]
    matcher --> endpoint[Supported Vault endpoint]
    endpoint --> edge[Specific or generic access edge]
    edge --> target[Observed, synthetic, or potential target]
```

| Form | Behavior |
| --- | --- |
| Exact object path | Targets the observed object or creates a detached synthetic target. |
| `+` segment | Matches exactly one path segment. |
| Trailing `*` | Expands to compatible observed descendants and may retain an unobserved-creation anchor. |
| Identity template | Emits a rendered effective relationship from the identity representation referenced by the expression. |

The collector does not treat all capabilities as interchangeable. `read` on KV data, `read` on PKI issuer configuration, `update` on Transit decrypt, and `sudo` on token accessor listing map to different outcomes.

## Policy Evidence Properties

| Property | Meaning |
| --- | --- |
| `Capabilities` | Capabilities needed for the exported operation. |
| `Matched Paths` | Concrete or rendered request paths. |
| `Matched Policy Paths` | Original HCL paths. |
| `Scopes` | Exact, pattern, collection, subtree, mount, or similar scope. |
| `Surfaces` | Endpoint family, such as KV metadata or PKI issue. |
| `Operations` | Human-readable actions represented by the relationship. |
| `Requirements` | Known runtime or endpoint prerequisites. |
| `Via Policies` | Policies contributing to a derived effective relationship. |
| `Policy Origins` | Direct, group-inherited, auth-role, or other provenance. |

Properties that merge evidence from multiple matching path blocks are arrays. The raw policy remains available on the policy node, so access edges keep the context needed to understand the represented operation rather than repeating the entire policy.

## Deny, Sudo, And Parameters

`deny` is represented by `Vault_DenyAccess` and overrides grants for matching paths. `sudo` is included only for endpoints that Vault documents or enforces as sudo-gated; its presence in a broad policy block is not copied to unrelated edges.

`allowed_parameters`, `denied_parameters`, and `required_parameters` are retained and consulted for parameter-aware outcomes. For example, an unrestricted password replacement can become `Vault_ControlObject`, while a constrained mutation may remain `Vault_ManageObject` or `Vault_PotentialAccess`.

## Policy As Source Of Truth

Policy-to-target edges remain visible even when a derived identity-specific attack path exists. This allows analysts to answer both questions:

- Which policy declares this authority?
- Which concrete identity or controlled object can exercise it?

VaultHound intentionally avoids materializing every non-templated policy grant as a duplicate entity-to-resource relationship. Policy assignment and group membership already provide the traversable path to the declared authority.

## Limitations

- Runtime control groups, Sentinel decisions, quotas, response wrapping, and token state can affect an otherwise valid ACL operation.
- A broad create right may affect future objects that are absent from collection; that remains non-traversable or potential.
- Enterprise policy types outside ordinary ACL path semantics are not assumed to behave like ACL policies solely because their registry path is recorded.
