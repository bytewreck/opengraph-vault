# Identity Store

The Identity Store represents Vault's namespace-local identity subsystem under `identity/`. It contains canonical identities, external identity mappings, outbound OIDC resources, MFA configuration, and Enterprise SCIM clients.

```mermaid
flowchart LR
    namespace[Vault_Namespace] -->|Vault_Contains| store[Vault_Store: IDENTITY]
    store -->|Vault_Contains| entity[Entities]
    store -->|Vault_Contains| group[Groups]
    store -->|Vault_Contains| oidc[OIDC resources]
    store -->|Vault_Contains| mfa[MFA resources]
    store -->|Vault_Contains| scim[Vault_ScimClient]
```

The store is the destination for collection-wide list/create and identity configuration rights. Exact reads and management rights target concrete identity objects.

## Nodes

| Node | Description |
| --- | --- |
| `Vault_Entity` | Canonical identity with direct policies, effective groups, metadata, aliases, creation time, and update time. |
| `Vault_EntityAlias` | Auth-mount-specific external name that resolves to a canonical entity. |
| `Vault_Group` | Internal or external group with policies, member entities, child groups, aliases, and metadata. |
| `Vault_GroupAlias` | External group name on an auth mount that resolves to a canonical group. |
| `Vault_OidcApplication` | Outbound OIDC client application configured to trust Vault as an identity provider. |
| `Vault_OidcKey` | Signing key used by outbound OIDC applications or providers. |
| `Vault_OidcAssignment` | Assignment object selecting entities or groups that may access applications. |
| `Vault_OidcProvider` | Outbound OIDC provider configuration where Vault acts as the identity provider. |
| `Vault_OidcScope` | OIDC scope and claim template exposed by a provider. |
| `Vault_OidcTokenRole` | Named identity-token signing role. |
| `Vault_MfaMethod` | Configured MFA method, such as TOTP, Duo, Okta, or PingID. |
| `Vault_MfaLoginEnforcement` | Rule that applies one or more MFA methods to selected identities or auth surfaces. |
| `Vault_ScimClient` | Enterprise SCIM client and access-grant configuration. |

## Identity Resolution

Auth-specific principals do not replace canonical Vault identity. Where mount accessor and name correlation are available, they resolve through aliases.

```mermaid
flowchart LR
    principal[Vault_AuthUser or Vault_AuthGroup] -->|Vault_MapsTo| alias[Entity or Group Alias]
    alias -->|Vault_MapsTo| identity[Vault_Entity or Vault_Group]
    alias -->|Vault_OnAuthMethod| method[Vault_AuthMethod]
    entity[Vault_Entity] -->|Vault_MemberOf| group[Vault_Group]
    child[Vault_Group] -->|Vault_MemberOf| parent[Vault_Group]
    identity -->|Vault_LinksPolicy| policy[Vault_Policy]
```

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | --- | --- |
| `Vault_MapsTo` | Auth principal or alias | Alias or canonical identity | Yes | Correlates an external representation with Vault identity. |
| `Vault_OnAuthMethod` | Entity or group alias | Auth method | No | Records the mount accessor on which the alias exists. |
| `Vault_MemberOf` | Entity or child group | Group | Yes | Carries policy-bearing membership. |
| `Vault_LinksPolicy` | Entity or group | Policy | Yes | Direct or inherited policy assignment, with link type properties. |

Group membership returned by Vault is modeled; VaultHound does not independently query external directories to prove upstream membership.

## Identity Administration

```mermaid
flowchart LR
    policy[Vault_Policy] -->|Vault_ListObjects| store[Identity Store]
    policy -->|Vault_CreateObject| store
    policy -->|Vault_ReadIdentity| object[Entity, alias, group, or identity service]
    policy -->|Vault_ManageObject| object
    policy -->|Vault_ControlObject| controlled[Takeover-capable identity target]
    controlled -->|Vault_LinksPolicy| granted[Vault_Policy]
```

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | --- | --- |
| `Vault_ListObjects` | Policy | Identity Store | No | Lists entity, alias, group, OIDC, MFA, or SCIM collections. |
| `Vault_CreateObject` | Policy | Identity Store or synthetic exact target | No | Creates an identity-subsystem object. |
| `Vault_ReadIdentity` | Policy | Concrete object or Identity Store | No | Reads non-secret identity data or a store-native identity surface. |
| `Vault_ReadCredential` | Policy | Secret-bearing OIDC or MFA object | Yes | Reads returned credential material such as a confidential OIDC client secret. |
| `Vault_ReadObject` | Policy | Concrete generic identity object | No | Reads durable configuration through the generic family. |
| `Vault_ManageObject` | Policy | Concrete identity object | No | Updates or deletes ordinary identity configuration. |
| `Vault_ControlObject` | Policy | Concrete entity, group, or trust target | Yes | Performs a parameter-aware mutation that proves identity takeover. |
| `Vault_ReadConfig` | Policy | Identity Store | No | Reads subsystem configuration such as OIDC configuration. |
| `Vault_ManageConfig` | Policy | Identity Store | No | Changes subsystem-wide configuration. |
| `Vault_DenyAccess` | Policy | Matching target | No | Preserves an overriding deny rule. |
| `Vault_PotentialAccess` | Policy or resolved principal | Unresolved target | No | Records an unproven identity-control or credential outcome. |

Creating or managing an object is not automatically traversable. `Vault_ControlObject` is derived only when the controlled parameters establish a concrete takeover mechanism, such as changing canonical alias ownership, adding an attacker-controlled entity to a policy-bearing internal group, or replacing unrestricted trust configuration.

### Attack Paths

Identity takeover can expose every policy linked to the controlled identity object:

```mermaid
flowchart LR
    policyA["Vault_Policy A"] -->|Vault_ControlObject| group[Vault_Group]
    group -->|Vault_LinksPolicy| policyB["Vault_Policy B"]
```

This path reaches only policies observed as linked to the controlled group. Policy-assignment parameters remain evidence on the relevant management or control edge and do not create a direct policy-to-policy relationship.

Rebinding an alias under attacker control targets the candidate canonical identity directly:

```mermaid
flowchart LR
    policyA["Vault_Policy A"] -->|Vault_ControlObject| identity["Vault_Entity or Vault_Group"]
    identity -->|Vault_LinksPolicy| policyB["Vault_Policy B"]
```

The `Vault_ControlObject` properties distinguish this path from membership takeover:

| Control Method | Control Target | Via Object |
| --- | --- | --- |
| `Modify Group Membership` | Internal `Vault_Group` | Membership parameters on the group operation |
| `Rebind Controlled Entity Alias` | Candidate `Vault_Entity` | Controlled `Vault_EntityAlias` in `Via Object IDs` and `Via Object Names` |
| `Rebind Controlled Group Alias` | Candidate `Vault_Group` | Controlled `Vault_GroupAlias` in `Via Object IDs` and `Via Object Names` |

No additional alias hop follows `Vault_ControlObject`: the collector derives control over the canonical entity or group selected by the alias rebinding operation.

```mermaid
flowchart LR
    policy[Vault_Policy] -->|Vault_ReadCredential| credential["Vault_OidcApplication or Vault_MfaMethod"]
```

This path is emitted only when the authenticated read returns usable secret material, such as a confidential OIDC client secret or an enrollment/integration credential. Ordinary identity reads remain non-traversable.

## Outbound OIDC

The outbound OIDC model is distinct from the JWT/OIDC authentication method. Here Vault is the identity provider and applications consume Vault-issued identity tokens.

```mermaid
flowchart LR
    provider[Vault_OidcProvider] -->|Vault_OidcAllowsApplication| app[Vault_OidcApplication]
    provider -->|Vault_OidcSupportsScope| scope[Vault_OidcScope]
    app -->|Vault_References| key[Vault_OidcKey]
    principal[Vault_Entity or Vault_Group] -->|Vault_OidcAssignedTo| assignment[Vault_OidcAssignment]
    assignment -->|Vault_OidcGrantsAccess| app
    entity[Vault_Entity] -->|Vault_OidcAuthenticateTo| app
```

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | --- | --- |
| `Vault_OidcAllowsApplication` | Provider | Application | No | Provider configuration allows the client application. |
| `Vault_OidcSupportsScope` | Provider | Scope | No | Provider exposes the scope. |
| `Vault_References` | Application or provider | OIDC key | No | Configuration uses the signing key. |
| `Vault_OidcAssignedTo` | Entity or group | Assignment | No | Principal is selected by the assignment. |
| `Vault_OidcGrantsAccess` | Assignment | Application | No | Assignment grants application eligibility. |
| `Vault_OidcAuthorize` | Policy | Provider or application target | No | ACL permits the authenticated authorization surface. |
| `Vault_OidcAuthenticateTo` | Entity | Application | Yes | Assignment and provider constraints compose into proven application access. |
| `Vault_GenerateIdentityToken` | Policy | OIDC token role | Yes | Policy can invoke a concrete identity-token signing role. |

The direct authentication edge is derived from collected configuration; the intermediate assignment and provider edges remain visible as non-traversable evidence.

### Attack Paths

```mermaid
flowchart LR
    entity[Vault_Entity] -->|Vault_OidcAuthenticateTo| application[Vault_OidcApplication]
```

This derived edge requires an applicable assignment, an allowing provider, and compatible application/provider configuration. The assignment and provider edges alone do not create an attack path.

```mermaid
flowchart LR
    policy[Vault_Policy] -->|Vault_GenerateIdentityToken| role[Vault_OidcTokenRole]
```

The path represents the ability to mint a Vault identity token through an observed signing role. If the role's signing-key allowlist is empty or incompatible, no attack edge is emitted; an unresolved signing key produces `Vault_PotentialAccess`.

## MFA

```mermaid
flowchart LR
    enforcement -->|Vault_MfaAppliesTo| target[Entity, group, or auth method]
    enforcement[Vault_MfaLoginEnforcement] -->|Vault_MfaUsesMethod| method[Vault_MfaMethod]
    policy[Vault_Policy] -->|Vault_MfaSelfEnroll| method
    policy -->|Vault_MfaGenerateSecret| method
    policy -->|Vault_PotentialAccess| entity[Vault_Entity]
```

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | --- | --- |
| `Vault_MfaUsesMethod` | MFA login enforcement | MFA method | No | Records the method required or referenced by the enforcement. |
| `Vault_MfaAppliesTo` | MFA login enforcement | Entity, group, or auth method | No | Records the collected identity or login surface governed by the enforcement. |
| `Vault_MfaSelfEnroll` | Policy | MFA method | No | Permits MFA self-enrollment. |
| `Vault_MfaGenerateSecret` | Policy | MFA method | No | Generates enrollment secret material where supported. |
| `Vault_PotentialAccess` | Policy | Entity or Identity Store | No | Records administrative TOTP enrollment material without proving the entity's primary credential. |

MFA methods and enforcements describe login prerequisites. The collector does not perform enrollment or login challenges.

### Attack Paths

MFA topology edges and self-enrollment permissions are non-traversable because configuration or enrollment eligibility does not by itself bypass MFA. `identity/mfa/method/totp/admin-generate` resolves `entity_id` parameter constraints to observed entities and emits `Vault_PotentialAccess` with the returned TOTP enrollment secret, the primary-credential prerequisite, and the requirement that no enrollment exists or that it can first be destroyed. An unresolved entity selector remains anchored to the Identity Store. This is deliberately not `Vault_ReadCredential`: a TOTP seed alone is only one factor and does not prove control of the entity's primary login.

## SCIM

```mermaid
flowchart LR
    client[Vault_ScimClient] -.->|Vault_ScimUsesPrincipal| principal[Access-grant Vault_Entity]
    client -.->|Vault_ScimManages| resource["Client-owned Vault_Entity or Vault_Group"]
    policy[Vault_Policy] -.->|Vault_ScimProtocolAccess| client
    principal -.->|Vault_ScimReadResources| client
    principal -.->|Vault_ScimProvisionResources| resource
    principal -.->|Vault_PotentialAccess| client
```

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | --- | --- |
| `Vault_ScimUsesPrincipal` | SCIM client | Entity | No | Identifies the client's configured access-grant principal. |
| `Vault_ScimManages` | SCIM client | Entity or group | No | Records that the resource is owned by that SCIM client. |
| `Vault_ScimProtocolAccess` | Policy | SCIM client | No | Declared ACL access to authenticated SCIM surfaces. |
| `Vault_ScimReadResources` | Access-grant entity | SCIM client | No | Derived effective permission to query, read, list, or discover SCIM resources. |
| `Vault_ScimProvisionResources` | Access-grant entity | Observed entity or group | No | Derived effective permission to create, update, patch, or delete the concrete client-owned resource. |
| `Vault_PotentialAccess` | Access-grant entity | SCIM client | No | Provisioning may create an unobserved resource, or target ownership and resolution are incomplete. |

`Vault_ScimProtocolAccess` preserves the declaring policy's authority but does not prove that the policy belongs to the client's configured access-grant principal. Effective read and provisioning relationships are derived only after that principal resolves to an enabled entity and its effective ACLs are evaluated. Provisioning reaches an observed client-owned resource directly; collection creation and unresolved targets remain potential access anchored to the client.

### Attack Paths

SCIM read, protocol, provisioning, ownership, and principal relationships are currently non-traversable evidence. `Vault_ScimManages` describes configured ownership but is not used as a containment fan-out or attack-path hop. This prevents read-only, collection-level, or unresolved SCIM access from implying control of every entity and group.

## Template Policies

Identity templates can reference entity fields, an entity alias on a specific accessor, or an identity group by ID. The rendered effective edge originates from the referenced identity representation:

| Template reference | Effective source |
| --- | --- |
| `identity.entity.*` | `Vault_Entity` |
| `identity.entity.aliases.<accessor>.*` | Matching `Vault_EntityAlias` |
| `identity.groups.ids.<group-id>.*` | Referenced `Vault_Group` |

Policy inheritance from a group remains provenance on the edge. It does not make the group the source unless the template expression itself references that group.

### Attack Paths

A rendered template edge can originate directly from the referenced entity representation and reach a concrete subsystem target. The destination subsystem documents the resulting security edge, such as `Vault_KvReadSecret` in the [KV section](MOUNTS.md#kv). `Matched Policy Paths`, rendered `Matched Paths`, and `Via Policies` preserve why the effective identity-specific edge exists.

## Limitations

- External identity-provider state is not independently validated.
- Login MFA, control groups, Sentinel policy, quotas, and token wrapping can add runtime conditions beyond static ACLs.
- Sensitive-read edges identify returned secret fields but do not exercise the credential.
- SCIM and OIDC behavior depends on Enterprise features and Vault version.
