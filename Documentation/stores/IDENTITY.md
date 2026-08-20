# Identity Store

The Identity Store represents Vault's namespace-local identity subsystem under `identity/`. It contains canonical identities, external identity mappings, outbound OIDC resources, MFA configuration, and Enterprise SCIM clients.

## Glob, Synthetic, And Control Behavior

- Collection globs expand read and manage rights to compatible observed identity objects.
- Exact missing object names may create detached synthetic targets without asserting that the object exists.
- Collection-wide creation remains anchored to the Identity Store with object-type and creation evidence.
- `Vault_ControlObject` is emitted only when parameter-aware mutation proves a concrete identity or trust takeover.
- Templated paths derive effective principal-to-target edges only after their referenced identity fields resolve.

## Limitations

- VaultHound does not authenticate as collected entities or validate external identity-provider credentials.
- External directory membership is represented only where Vault returns aliases or mappings that prove it.
- Runtime MFA challenges, control groups, and token state can impose conditions not visible from static ACLs.
- SCIM provisioning is conditional on the configured access-grant principal and collected client ownership.

## Common Topology

```mermaid
flowchart LR
    namespace[Vault_Namespace]:::namespaceNode -->|Vault_Contains| store[Vault_Store: IDENTITY]:::storeNode
    store -->|Vault_Contains| entity[Entities]:::entityNode
    store -->|Vault_Contains| group[Groups]:::groupNode
    store -->|Vault_Contains| oidc[OIDC resources]:::oidcNode
    store -->|Vault_Contains| mfa[MFA resources]:::mfaNode
    store -->|Vault_Contains| scim[Vault_ScimClient]:::scimNode

    classDef namespaceNode fill:#6C757D,color:#fff,stroke:#343A40,stroke-width:2px
    classDef storeNode fill:#5F6B7A,color:#fff,stroke:#343A40,stroke-width:2px
    classDef entityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef groupNode fill:#219653,color:#fff,stroke:#145A32,stroke-width:2px
    classDef oidcNode fill:#16A085,color:#fff,stroke:#0E6655,stroke-width:2px
    classDef mfaNode fill:#D35400,color:#fff,stroke:#873600,stroke-width:2px
    classDef scimNode fill:#2471A3,color:#fff,stroke:#154360,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (:Vault_Namespace)-[:Vault_Contains]->(:Vault_Store)-[:Vault_Contains]->(n)
WHERE n:Vault_Entity
   OR n:Vault_EntityAlias
   OR n:Vault_Group
   OR n:Vault_GroupAlias
   OR n:Vault_OidcApplication
   OR n:Vault_OidcKey
   OR n:Vault_OidcAssignment
   OR n:Vault_OidcProvider
   OR n:Vault_OidcScope
   OR n:Vault_OidcTokenRole
   OR n:Vault_MfaMethod
   OR n:Vault_MfaLoginEnforcement
   OR n:Vault_ScimClient
RETURN p
```

The store is the destination for collection-wide list/create and identity configuration rights. Exact reads and management rights target concrete identity objects.

### Common Nodes

| Type | Meaning |
| --- | --- |
| `Vault_Entity` | Canonical identity with direct policies, effective groups, metadata, aliases, creation time, and update time. |
| `Vault_EntityAlias` | Auth-mount-specific external name that resolves to a canonical entity. |
| `Vault_Group` | Internal or external group with policies, member entities, child groups, aliases, and metadata. |
| `Vault_GroupAlias` | External group name on an auth mount that resolves to a canonical group. |

### Common Edges

Auth-specific principals do not replace canonical Vault identity. Where mount accessor and name correlation are available, they resolve through aliases.

```mermaid
flowchart LR
    EA[Vault_EntityAlias]:::entityAliasNode -->|Vault_MapsTo| VE[Vault_Entity]:::entityNode
    EA -->|Vault_LinksPolicy| P1[Vault_Policy]:::policyNode
    VE -->|Vault_LinksPolicy| P2[Vault_Policy]:::policyNode
    GA[Vault_GroupAlias]:::groupAliasNode -->|Vault_MapsTo| VG[Vault_Group]:::groupNode
    GA -->|Vault_LinksPolicy| P1
    VG -->|Vault_LinksPolicy| P2
    VE -->|Vault_MemberOf| VG
  
    classDef entityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef entityAliasNode fill:#56CCF2,color:#111,stroke:#2E86C1,stroke-width:2px
    classDef groupNode fill:#219653,color:#fff,stroke:#145A32,stroke-width:2px
    classDef groupAliasNode fill:#6FCF97,color:#111,stroke:#239B56,stroke-width:2px
    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (s)-[:Vault_MapsTo|Vault_OnAuthMethod|Vault_MemberOf|Vault_LinksPolicy*1..3]->(d)
WHERE (s:Vault_AuthUser OR s:Vault_AuthGroup OR s:Vault_Entity OR s:Vault_Group)
  AND (d:Vault_EntityAlias OR d:Vault_GroupAlias OR d:Vault_Entity OR d:Vault_Group OR d:Vault_AuthMethod OR d:Vault_Policy)
RETURN p
```

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | :---: | --- |
| `Vault_MapsTo` | Auth principal or alias | Alias or canonical identity | :white_check_mark: | Correlates an external representation with Vault identity. |
| `Vault_OnAuthMethod` | Entity or group alias | Auth method | :x: | Records the mount accessor on which the alias exists. |
| `Vault_MemberOf` | Entity or child group | Group | :white_check_mark: | Carries policy-bearing membership. |
| `Vault_LinksPolicy` | Entity or group | Policy | :white_check_mark: | Direct or inherited policy assignment, with link type properties. |

Group membership returned by Vault is modeled; VaultHound does not independently query external directories to prove upstream membership.

### Common Properties

| Node/Edge Type | Property | Description |
| --- | --- | --- |
| `Vault_Entity` | `Entity ID` | Records Vault's canonical identity identifier. |
| `Vault_Entity` | `Entity Name` | Records the canonical identity's display name. |
| `Vault_Entity` | `Disabled` | Indicates whether authentication through the entity is disabled. |
| `Vault_Entity` | `Bucket Key Hash` | Records Vault's internal storage-bucket hash for the entity. |
| `Vault_Entity` | `External ID` | Records the external identifier associated with the entity when present. |
| `Vault_Entity` | `Policies` | Lists policies assigned directly to the entity. |
| `Vault_Entity` | `Entity Alias IDs` | Lists aliases that resolve to the entity. |
| `Vault_Entity` | `Direct Group IDs` | Lists groups in which the entity has direct membership. |
| `Vault_Entity` | `Effective Group IDs` | Lists all groups affecting the entity after hierarchy expansion. |
| `Vault_Entity` | `Inherited Group IDs` | Lists effective groups reached through nested group membership. |
| `Vault_Entity` | `Merged Entity IDs` | Lists canonical entities merged into this entity. |
| `Vault_Entity` | `SCIM Client ID` | Identifies the SCIM client that owns the entity when SCIM-managed. |
| `Vault_Entity` | `SCIM Managed` | Indicates whether the entity is managed through SCIM. |
| `Vault_Entity` | `Creation Time` | Records when Vault created the entity. |
| `Vault_Entity` | `Last Update Time` | Records the entity's most recent update time. |
| `Vault_EntityAlias` | `Entity Alias ID` | Records Vault's stable identifier for the entity alias. |
| `Vault_EntityAlias` | `Entity Alias Name` | Records the external login name represented by the alias. |
| `Vault_EntityAlias` | `Mount Path` | Identifies the auth mount path on which the alias exists. |
| `Vault_EntityAlias` | `Mount Accessor` | Identifies the auth mount accessor used to resolve the alias. |
| `Vault_EntityAlias` | `Mount Type` | Identifies the authentication backend type associated with the alias. |
| `Vault_EntityAlias` | `Entity ID` | Identifies the canonical entity to which the alias resolves. |
| `Vault_EntityAlias` | `Local` | Indicates whether the alias is local to the performance replication cluster. |
| `Vault_EntityAlias` | `Merged From Canonical IDs` | Lists prior canonical IDs represented after entity merging. |
| `Vault_EntityAlias` | `Creation Time` | Records when Vault created the alias. |
| `Vault_EntityAlias` | `Last Update Time` | Records the alias's most recent update time. |
| `Vault_Group` | `Group ID` | Records Vault's canonical group identifier. |
| `Vault_Group` | `Group Name` | Records the group's display name. |
| `Vault_Group` | `Group Type` | Identifies whether the group is internal or external. |
| `Vault_Group` | `Policies` | Lists policies assigned directly to the group. |
| `Vault_Group` | `Member Entity IDs` | Lists entities with direct membership in the group. |
| `Vault_Group` | `Member Group IDs` | Lists child groups directly included in the group. |
| `Vault_Group` | `Parent Group IDs` | Lists groups that contain this group. |
| `Vault_Group` | `Modify Index` | Records Vault's modification index for the group. |
| `Vault_Group` | `SCIM Client ID` | Identifies the SCIM client that owns the group when SCIM-managed. |
| `Vault_Group` | `SCIM Managed` | Indicates whether the group is managed through SCIM. |
| `Vault_Group` | `Creation Time` | Records when Vault created the group. |
| `Vault_Group` | `Last Update Time` | Records the group's most recent update time. |
| `Vault_GroupAlias` | `Group Alias ID` | Records Vault's stable identifier for the group alias. |
| `Vault_GroupAlias` | `Group Alias Name` | Records the external group name represented by the alias. |
| `Vault_GroupAlias` | `Mount Path` | Identifies the auth mount path on which the group alias exists. |
| `Vault_GroupAlias` | `Mount Accessor` | Identifies the auth mount accessor used to resolve the group alias. |
| `Vault_GroupAlias` | `Mount Type` | Identifies the authentication backend type associated with the group alias. |
| `Vault_GroupAlias` | `Group ID` | Identifies the canonical group to which the alias resolves. |
| `Vault_GroupAlias` | `Local` | Indicates whether the group alias is local to the performance replication cluster. |
| `Vault_GroupAlias` | `Merged From Canonical IDs` | Lists prior canonical group IDs represented after merging. |
| `Vault_GroupAlias` | `Creation Time` | Records when Vault created the group alias. |
| `Vault_GroupAlias` | `Last Update Time` | Records the group alias's most recent update time. |
| `Vault_LinksPolicy` | `Policy Link Types` | Distinguishes direct entity assignment, group assignment or inheritance, and other configured policy-grant sources. |

## Identity Administration

```mermaid
flowchart LR
    policy[Vault_Policy]:::policyNode -->|Vault_ListObjects| store[Vault_Store: IDENTITY]:::storeNode
    policy -->|Vault_CreateObject| store
    policy -->|Vault_ReadIdentity| object[Entity, alias, group, or identity service]:::identityNode
    policy -->|Vault_ManageObject| object
    policy -->|Vault_ControlObject| controlled[Takeover-capable identity target]:::identityNode
    controlled -->|Vault_LinksPolicy| granted[Vault_Policy]:::policyNode

    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
    classDef storeNode fill:#5F6B7A,color:#fff,stroke:#343A40,stroke-width:2px
    classDef identityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (:Vault_Policy)-[:Vault_ListObjects|Vault_CreateObject|Vault_ReadIdentity|Vault_ManageObject|Vault_ControlObject|Vault_LinksPolicy*1..2]->(d)
WHERE d:Vault_Store
   OR d:Vault_Entity
   OR d:Vault_EntityAlias
   OR d:Vault_Group
   OR d:Vault_GroupAlias
   OR d:Vault_Policy
RETURN p
```

### Nodes

Identity administration introduces no additional durable object kind. It targets the Identity `Vault_Store` for collection-wide operations and the concrete core identity, OIDC, MFA, or SCIM nodes catalogued in their respective sections.

### Edges

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | :---: | --- |
| `Vault_ListObjects` | Policy | Identity Store | :x: | Lists entity, alias, group, OIDC, MFA, or SCIM collections. |
| `Vault_CreateObject` | Policy | Identity Store or synthetic exact target | :x: | Creates an identity-subsystem object. |
| `Vault_ReadIdentity` | Policy | Concrete object or Identity Store | :x: | Reads non-secret identity data or a store-native identity surface. |
| `Vault_ReadCredential` | Policy | Secret-bearing OIDC or MFA object | :white_check_mark: | Reads returned credential material such as a confidential OIDC client secret. |
| `Vault_ReadObject` | Policy | Concrete generic identity object | :x: | Reads durable configuration through the generic family. |
| `Vault_ManageObject` | Policy | Concrete identity object | :x: | Updates or deletes ordinary identity configuration. |
| `Vault_ControlObject` | Policy | Concrete entity, group, or trust target | :white_check_mark: | Performs a parameter-aware mutation that proves identity takeover. |
| `Vault_ReadConfig` | Policy | Identity Store | :x: | Reads subsystem configuration such as OIDC configuration. |
| `Vault_ManageConfig` | Policy | Identity Store | :x: | Changes subsystem-wide configuration. |
| `Vault_DenyAccess` | Policy | Matching target | :x: | Preserves an overriding deny rule. |
| `Vault_PotentialAccess` | Policy or resolved principal | Unresolved target | :x: | Records an unproven identity-control or credential outcome. |

Creating or managing an object is not automatically traversable. `Vault_ControlObject` is derived only when the controlled parameters establish a concrete takeover mechanism, such as changing canonical alias ownership, adding an attacker-controlled entity to a policy-bearing internal group, or replacing unrestricted trust configuration.

### Properties

| Node/Edge Type | Property | Description |
| --- | --- | --- |
| `Vault_ListObjects`<br>`Vault_CreateObject`<br>`Vault_ReadObject`<br>`Vault_ManageObject` | `Object Types` | Identifies the identity collection or concrete object kinds represented by the generic edge. |
| `Vault_ListObjects`<br>`Vault_CreateObject`<br>`Vault_ReadObject`<br>`Vault_ManageObject` | `Operations` | Lists the endpoint operations folded into the generic edge. |
| `Vault_ReadIdentity` | `Identity Targets` | Identifies the entity, group, alias, lookup, or identity-service data that can be read. |
| `Vault_ReadIdentity` | `Operations` | Lists the authenticated identity-read operations represented by the edge. |
| `Vault_ReadCredential` | `Identity Targets` | Identifies the secret-bearing OIDC or MFA object read by the policy. |
| `Vault_ReadCredential` | `Operations` | Lists the authenticated read operations that return credential material. |
| `Vault_ReadCredential` | `Exposure Confirmed` | Indicates that the authenticated response is proven to return usable credential material. |
| `Vault_ReadConfig`<br>`Vault_ManageConfig` | `Config Targets` | Names the identity-wide configuration surface, such as outbound OIDC or MFA configuration. |
| `Vault_ReadConfig`<br>`Vault_ManageConfig` | `Operations` | Lists the configuration operations represented by the edge. |
| `Vault_ControlObject` | `Control Methods` | Identifies the concrete identity-takeover mechanism proven by the operation. |
| `Vault_ControlObject` | `Control Parameters` | Lists the request parameters whose mutation establishes control. |
| `Vault_ControlObject` | `Impacts` | Describes the security outcomes made possible by controlling the target. |
| `Vault_ControlObject` | `Assignable Policies` | Lists policies that the operation can assign to the controlled object when known. |
| `Vault_ControlObject` | `Policy Assignment Parameters` | Identifies request parameters that can alter policy assignment. |
| `Vault_ControlObject` | `Via Object IDs` | Identifies an intermediate controlled alias or object used to prove takeover. |
| `Vault_ControlObject` | `Via Object Names` | Names the intermediate controlled alias or object used to prove takeover. |
| `Vault_PotentialAccess` | `Potential Outcomes` | Describes the identity-control or credential outcome that could become available. |
| `Vault_PotentialAccess` | `Requirements` | Lists unresolved prerequisites that prevent a traversable edge. |
| `Vault_PotentialAccess` | `Resolution Status` | Explains why the target or prerequisite could not be proven. |

### Attack Paths

Identity takeover can expose every policy linked to the controlled identity object:

```mermaid
flowchart LR
    policyA["Vault_Policy A"]:::policyNode -->|Vault_ControlObject| group[Vault_Group]:::groupNode
    group -->|Vault_LinksPolicy| policyB["Vault_Policy B"]:::policyNode

    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
    classDef groupNode fill:#219653,color:#fff,stroke:#145A32,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (:Vault_Policy)-[:Vault_ControlObject]->(:Vault_Group)-[:Vault_LinksPolicy]->(:Vault_Policy)
RETURN p
```

This path reaches only policies observed as linked to the controlled group. Policy-assignment parameters remain evidence on the relevant management or control edge and do not create a direct policy-to-policy relationship.

Rebinding an alias under attacker control targets the candidate canonical identity directly:

```mermaid
flowchart LR
    policyA["Vault_Policy A"]:::policyNode -->|Vault_ControlObject| identity["Vault_Entity or Vault_Group"]:::identityNode
    identity -->|Vault_LinksPolicy| policyB["Vault_Policy B"]:::policyNode

    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
    classDef identityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (:Vault_Policy)-[:Vault_ControlObject]->(identity)-[:Vault_LinksPolicy]->(:Vault_Policy)
WHERE identity:Vault_Entity OR identity:Vault_Group
RETURN p
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
    policy[Vault_Policy]:::policyNode -->|Vault_ReadCredential| credential["Vault_OidcApplication or Vault_MfaMethod"]:::credentialNode

    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
    classDef credentialNode fill:#B9770E,color:#fff,stroke:#7E5109,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (:Vault_Policy)-[:Vault_ReadCredential]->(credential)
WHERE credential:Vault_OidcApplication OR credential:Vault_MfaMethod
RETURN p
```

This path is emitted only when the authenticated read returns usable secret material, such as a confidential OIDC client secret or an enrollment/integration credential. Ordinary identity reads remain non-traversable.

## Outbound OIDC

The outbound OIDC model is distinct from the JWT/OIDC authentication method. Here Vault is the identity provider and applications consume Vault-issued identity tokens.

```mermaid
flowchart LR
    provider[Vault_OidcProvider]:::oidcProviderNode -->|Vault_OidcAllowsApplication| app[Vault_OidcApplication]:::oidcApplicationNode
    provider -->|Vault_OidcSupportsScope| scope[Vault_OidcScope]:::oidcScopeNode
    app -->|Vault_References| key[Vault_OidcKey]:::oidcKeyNode
    principal[Vault_Entity or Vault_Group]:::identityNode -->|Vault_OidcAssignedTo| assignment[Vault_OidcAssignment]:::oidcAssignmentNode
    assignment -->|Vault_OidcGrantsAccess| app
    entity[Vault_Entity]:::entityNode -->|Vault_OidcAuthenticateTo| app

    classDef oidcProviderNode fill:#16A085,color:#fff,stroke:#0E6655,stroke-width:2px
    classDef oidcApplicationNode fill:#1ABC9C,color:#111,stroke:#117864,stroke-width:2px
    classDef oidcScopeNode fill:#17A589,color:#fff,stroke:#0E6655,stroke-width:2px
    classDef oidcKeyNode fill:#B9770E,color:#fff,stroke:#7E5109,stroke-width:2px
    classDef oidcAssignmentNode fill:#2980B9,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef identityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef entityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (s)-[:Vault_OidcAllowsApplication|Vault_OidcSupportsScope|Vault_References|Vault_OidcAssignedTo|Vault_OidcGrantsAccess|Vault_OidcAuthenticateTo*1..3]->(d)
WHERE s:Vault_OidcProvider OR s:Vault_OidcApplication OR s:Vault_Entity OR s:Vault_Group
RETURN p
```

### Nodes

| Node | Description |
| --- | --- |
| `Vault_OidcApplication` | Outbound OIDC client application configured to trust Vault as its identity provider. |
| `Vault_OidcKey` | Signing key used by an outbound OIDC application, provider, or token role. |
| `Vault_OidcAssignment` | Assignment selecting entities or groups eligible to access applications. |
| `Vault_OidcProvider` | Provider configuration through which Vault exposes OIDC authorization and token endpoints. |
| `Vault_OidcScope` | Named scope and claims template exposed by a provider. |
| `Vault_OidcTokenRole` | Named role used to generate Vault identity tokens. |

### Edges

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | :---: | --- |
| `Vault_OidcAllowsApplication` | Provider | Application | :x: | Provider configuration allows the client application. |
| `Vault_OidcSupportsScope` | Provider | Scope | :x: | Provider exposes the scope. |
| `Vault_References` | Application or provider | OIDC key | :x: | Configuration uses the signing key. |
| `Vault_OidcAssignedTo` | Entity or group | Assignment | :x: | Principal is selected by the assignment. |
| `Vault_OidcGrantsAccess` | Assignment | Application | :x: | Assignment grants application eligibility. |
| `Vault_OidcAuthorize` | Policy | Provider or application target | :x: | ACL permits the authenticated authorization surface. |
| `Vault_OidcAuthenticateTo` | Entity | Application | :white_check_mark: | Assignment and provider constraints compose into proven application access. |
| `Vault_GenerateIdentityToken` | Policy | OIDC token role | :white_check_mark: | Policy can invoke a concrete identity-token signing role. |

The direct authentication edge is derived from collected configuration; the intermediate assignment and provider edges remain visible as non-traversable evidence.

### Properties

| Node/Edge Type | Property | Description |
| --- | --- | --- |
| `Vault_OidcApplication` | `Client ID` | Identifies the application in outbound OIDC requests. |
| `Vault_OidcApplication` | `Access Token TTL` | Records the configured access-token lifetime. |
| `Vault_OidcApplication` | `ID Token TTL` | Records the configured ID-token lifetime. |
| `Vault_OidcApplication` | `Client Secret Set` | Indicates whether the confidential application has a configured client secret. |
| `Vault_OidcApplication` | `Redirect URIs` | Lists the redirect destinations allowed for the application. |
| `Vault_OidcApplication` | `Assignments` | Lists assignment names allowed to access the application. |
| `Vault_OidcApplication` | `Key` | Names the OIDC signing key selected by the application. |
| `Vault_OidcApplication` | `Client Type` | Distinguishes public from confidential clients. |
| `Vault_OidcApplication` | `PKCE Requirement` | Records whether the client must use Proof Key for Code Exchange. |
| `Vault_OidcProvider` | `Issuer` | Records the provider issuer URL. |
| `Vault_OidcProvider` | `Allowed Client IDs` | Lists client IDs exposed by the provider; `*` permits every application. |
| `Vault_OidcProvider` | `Scopes Supported` | Lists scopes advertised by the provider. |
| `Vault_OidcProvider` | `Built In` | Indicates a Vault-provided provider object. |
| `Vault_OidcProvider` | `Delete Protected` | Indicates that Vault prevents deletion of the provider. |
| `Vault_OidcKey` | `Algorithm` | Identifies the signing algorithm used by the key. |
| `Vault_OidcKey` | `Allowed Client IDs` | Lists clients permitted to use the signing key. |
| `Vault_OidcKey` | `Rotation Period` | Records the automatic key-rotation interval. |
| `Vault_OidcKey` | `Verification TTL` | Records how long prior public keys remain available for token verification. |
| `Vault_OidcKey` | `Built In` | Indicates a Vault-provided signing key. |
| `Vault_OidcKey` | `Delete Protected` | Indicates that Vault prevents deletion of the key. |
| `Vault_OidcScope` | `Description` | Stores the human-readable scope description. |
| `Vault_OidcScope` | `Template` | Stores the claims template added when the scope is requested. |
| `Vault_OidcScope` | `Built In` | Indicates a Vault-provided scope. |
| `Vault_OidcScope` | `Immutable` | Indicates that the scope cannot be changed. |
| `Vault_OidcAssignment` | `Entity IDs` | Lists canonical entities selected by the assignment. |
| `Vault_OidcAssignment` | `Group IDs` | Lists canonical groups selected by the assignment. |
| `Vault_OidcAssignment` | `Built In` | Indicates a Vault-provided assignment. |
| `Vault_OidcAssignment` | `Immutable` | Indicates that the assignment cannot be changed. |
| `Vault_OidcTokenRole` | `Client ID` | Identifies the audience/client encoded into generated identity tokens. |
| `Vault_OidcTokenRole` | `Key` | Names the signing key used by the token role. |
| `Vault_OidcTokenRole` | `Template` | Stores the claims template used for generated identity tokens. |
| `Vault_OidcTokenRole` | `TTL` | Records the generated identity-token lifetime. |
| `Vault_References` | `Reference Types` | Classifies the referenced object as an OIDC signing key. |
| `Vault_References` | `Reference Evidence` | Identifies whether the reference came from an application or token-role key setting. |
| `Vault_References` | `Key References` | Preserves the configured signing-key name. |
| `Vault_OidcAuthenticateTo` | `Assignment Names` | Lists assignments that make the entity eligible for the application. |
| `Vault_OidcAuthenticateTo` | `Provider Names` | Lists providers through which the application can be reached. |
| `Vault_OidcAuthenticateTo` | `Matched Paths` | Lists authorization endpoints whose effective ACLs were evaluated. |
| `Vault_OidcAuthenticateTo` | `ACL Basis` | Explains the ACL evidence used to derive application access. |
| `Vault_GenerateIdentityToken`<br>`Vault_PotentialAccess` | `Key Eligibility` | Records whether each resolved signing key permits the token role's client ID. |
| `Vault_GenerateIdentityToken`<br>`Vault_PotentialAccess` | `Signing Key Names` | Lists signing keys considered for identity-token generation. |
| `Vault_GenerateIdentityToken` | `Eligible Role Names` | Lists observed token roles whose signing-key constraints are satisfied. |
| `Vault_PotentialAccess` | `Unresolved Role Names` | Lists token roles whose signing-key prerequisite could not be resolved. |
| `Vault_GenerateIdentityToken`<br>`Vault_PotentialAccess` | `Blocked Role Names` | Lists observed roles rejected by signing-key client restrictions. |

### Attack Paths

```mermaid
flowchart LR
    entity[Vault_Entity]:::entityNode -->|Vault_OidcAuthenticateTo| application[Vault_OidcApplication]:::oidcApplicationNode

    classDef entityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef oidcApplicationNode fill:#1ABC9C,color:#111,stroke:#117864,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (:Vault_Entity)-[:Vault_OidcAuthenticateTo]->(:Vault_OidcApplication)
RETURN p
```

This derived edge requires an applicable assignment, an allowing provider, and compatible application/provider configuration. The assignment and provider edges alone do not create an attack path.

```mermaid
flowchart LR
    policy[Vault_Policy]:::policyNode -->|Vault_GenerateIdentityToken| role[Vault_OidcTokenRole]:::oidcTokenRoleNode

    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
    classDef oidcTokenRoleNode fill:#148F77,color:#fff,stroke:#0B5345,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (:Vault_Policy)-[:Vault_GenerateIdentityToken]->(:Vault_OidcTokenRole)
RETURN p
```

The path represents the ability to mint a Vault identity token through an observed signing role. If the role's signing-key allowlist is empty or incompatible, no attack edge is emitted; an unresolved signing key produces `Vault_PotentialAccess`.

## MFA

```mermaid
flowchart LR
    enforcement -->|Vault_MfaAppliesTo| target[Entity, group, or auth method]:::identityNode
    enforcement[Vault_MfaLoginEnforcement]:::mfaEnforcementNode -->|Vault_MfaUsesMethod| method[Vault_MfaMethod]:::mfaMethodNode
    policy[Vault_Policy]:::policyNode -->|Vault_MfaSelfEnroll| method
    policy -->|Vault_MfaGenerateSecret| method
    policy -->|Vault_PotentialAccess| entity[Vault_Entity]:::entityNode

    classDef identityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef mfaEnforcementNode fill:#E67E22,color:#fff,stroke:#A04000,stroke-width:2px
    classDef mfaMethodNode fill:#D35400,color:#fff,stroke:#873600,stroke-width:2px
    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
    classDef entityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (s)-[:Vault_MfaAppliesTo|Vault_MfaUsesMethod|Vault_MfaSelfEnroll|Vault_MfaGenerateSecret|Vault_PotentialAccess*1..2]->(d)
WHERE s:Vault_MfaLoginEnforcement OR s:Vault_Policy
RETURN p
```

### Nodes

| Node | Description |
| --- | --- |
| `Vault_MfaMethod` | Configured MFA method, such as TOTP, Duo, Okta, or PingID. |
| `Vault_MfaLoginEnforcement` | Rule applying one or more MFA methods to selected identities or authentication surfaces. |

### Edges

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | :---: | --- |
| `Vault_MfaUsesMethod` | MFA login enforcement | MFA method | :x: | Records the method required or referenced by the enforcement. |
| `Vault_MfaAppliesTo` | MFA login enforcement | Entity, group, or auth method | :x: | Records the collected identity or login surface governed by the enforcement. |
| `Vault_MfaSelfEnroll` | Policy | MFA method | :x: | Permits MFA self-enrollment. |
| `Vault_MfaGenerateSecret` | Policy | MFA method | :x: | Generates enrollment secret material where supported. |
| `Vault_PotentialAccess` | Policy | Entity or Identity Store | :x: | Records administrative TOTP enrollment material without proving the entity's primary credential. |

MFA methods and enforcements describe login prerequisites. The collector does not perform enrollment or login challenges.

### Properties

| Node/Edge Type | Property | Description |
| --- | --- | --- |
| `Vault_MfaMethod` | `Method ID` | Identifies the MFA method. |
| `Vault_MfaMethod` | `Method Name` | Stores the configured MFA method name. |
| `Vault_MfaMethod` | `Method Type` | Identifies the MFA implementation, such as TOTP, Duo, Okta, or PingID. |
| `Vault_MfaMethod` | `Owning Namespace ID` | Identifies the namespace that owns the method. |
| `Vault_MfaMethod` | `Visible From Namespace IDs` | Lists namespaces from which the method is visible. |
| `Vault_MfaMethod` | `Issuer` | Records the issuer shown in generated TOTP enrollment information. |
| `Vault_MfaMethod` | `Algorithm` | Identifies the TOTP hash algorithm. |
| `Vault_MfaMethod` | `Digits` | Records the number of digits in generated TOTP codes. |
| `Vault_MfaMethod` | `Period` | Records the TOTP time-step duration. |
| `Vault_MfaMethod` | `Key Size` | Records the generated TOTP seed size. |
| `Vault_MfaMethod` | `QR Size` | Records the generated enrollment QR-code size. |
| `Vault_MfaMethod` | `Skew` | Records the accepted TOTP clock skew. |
| `Vault_MfaMethod` | `Max Validation Attempts` | Records the maximum failed validation attempts permitted by the method. |
| `Vault_MfaMethod` | `Self Enrollment Enabled` | Indicates whether users may enroll themselves. |
| `Vault_MfaMethod` | `Username Format` | Stores the external-provider username template. |
| `Vault_MfaMethod` | `API Hostname` | Identifies the external MFA provider API host. |
| `Vault_MfaMethod` | `Push Info` | Records provider-specific push-notification context. |
| `Vault_MfaMethod` | `Use Passcode` | Indicates whether passcode authentication is enabled. |
| `Vault_MfaMethod` | `Organization Name` | Stores the external MFA organization name. |
| `Vault_MfaMethod` | `Base URL` | Stores the external MFA provider base URL. |
| `Vault_MfaLoginEnforcement` | `Enforcement ID` | Identifies the MFA enforcement rule. |
| `Vault_MfaLoginEnforcement` | `MFA Method IDs` | Lists MFA methods that can satisfy the enforcement. |
| `Vault_MfaLoginEnforcement` | `Auth Method Accessors` | Lists auth mount accessors selected by the enforcement. |
| `Vault_MfaLoginEnforcement` | `Auth Method Types` | Lists auth backend types selected by the enforcement. |
| `Vault_MfaLoginEnforcement` | `Identity Entity IDs` | Lists canonical entities selected by the enforcement. |
| `Vault_MfaLoginEnforcement` | `Identity Group IDs` | Lists canonical groups selected by the enforcement. |
| `Vault_MfaLoginEnforcement` | `Satisfaction Mode` | Describes how configured MFA methods satisfy the enforcement. |
| `Vault_MfaLoginEnforcement` | `Method Selection Mode` | Describes how Vault chooses among configured MFA methods. |
| `Vault_MfaLoginEnforcement` | `Owning Namespace ID` | Identifies the namespace that owns the enforcement. |
| `Vault_MfaLoginEnforcement` | `Visible From Namespace IDs` | Lists namespaces from which the enforcement is visible. |
| `Vault_MfaAppliesTo` | `Selector Types` | Distinguishes entity, group, auth accessor, and auth-type selectors. |
| `Vault_MfaSelfEnroll`<br>`Vault_MfaGenerateSecret` | `Operations` | Lists the MFA enrollment operations represented by the edge. |
| `Vault_PotentialAccess` | `Potential Outcomes` | Identifies administrative TOTP enrollment as the possible result. |
| `Vault_PotentialAccess` | `Credential Types` | Identifies the returned enrollment material. |
| `Vault_PotentialAccess` | `Credential Uses` | Describes how the enrollment material could be used. |
| `Vault_PotentialAccess` | `Requirements` | Lists the primary-credential and enrollment-state prerequisites. |
| `Vault_PotentialAccess` | `Resolution Status` | Explains why administrative enrollment remains conditional. |

### Attack Paths

MFA topology edges and self-enrollment permissions are non-traversable because configuration or enrollment eligibility does not by itself bypass MFA. `identity/mfa/method/totp/admin-generate` resolves `entity_id` parameter constraints to observed entities and emits `Vault_PotentialAccess` with the returned TOTP enrollment secret, the primary-credential prerequisite, and the requirement that no enrollment exists or that it can first be destroyed. An unresolved entity selector remains anchored to the Identity Store. This is deliberately not `Vault_ReadCredential`: a TOTP seed alone is only one factor and does not prove control of the entity's primary login.

## SCIM

```mermaid
flowchart LR
    client[Vault_ScimClient]:::scimNode -.->|Vault_ScimUsesPrincipal| principal[Access-grant Vault_Entity]:::entityNode
    client -.->|Vault_ScimManages| resource["Client-owned Vault_Entity or Vault_Group"]:::identityNode
    policy[Vault_Policy]:::policyNode -.->|Vault_ScimProtocolAccess| client
    principal -.->|Vault_ScimReadResources| client
    principal -.->|Vault_ScimProvisionResources| resource
    principal -.->|Vault_PotentialAccess| client

    classDef scimNode fill:#2471A3,color:#fff,stroke:#154360,stroke-width:2px
    classDef entityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef identityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef policyNode fill:#C0392B,color:#fff,stroke:#7B241C,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (s)-[:Vault_ScimUsesPrincipal|Vault_ScimManages|Vault_ScimProtocolAccess|Vault_ScimReadResources|Vault_ScimProvisionResources|Vault_PotentialAccess*1..2]->(d)
WHERE s:Vault_ScimClient OR s:Vault_Policy OR s:Vault_Entity
RETURN p
```

### Nodes

| Node | Description |
| --- | --- |
| `Vault_ScimClient` | Enterprise SCIM client and access-grant configuration. |
| `Vault_Entity` | Canonical identity that may act as the SCIM access-grant principal or a managed User resource. |
| `Vault_Group` | Canonical group that may be managed as a SCIM Group resource. |

### Edges

| Edge | Source | Destination | Traversable | Meaning |
| --- | --- | --- | :---: | --- |
| `Vault_ScimUsesPrincipal` | SCIM client | Entity | :x: | Identifies the client's configured access-grant principal. |
| `Vault_ScimManages` | SCIM client | Entity or group | :x: | Records that the resource is owned by that SCIM client. |
| `Vault_ScimProtocolAccess` | Policy | SCIM client | :x: | Declared ACL access to authenticated SCIM surfaces. |
| `Vault_ScimReadResources` | Access-grant entity | SCIM client | :x: | Derived effective permission to query, read, list, or discover SCIM resources. |
| `Vault_ScimProvisionResources` | Access-grant entity | Observed entity or group | :x: | Derived effective permission to create, update, patch, or delete the concrete client-owned resource. |
| `Vault_PotentialAccess` | Access-grant entity | SCIM client | :x: | Provisioning may create an unobserved resource, or target ownership and resolution are incomplete. |

`Vault_ScimProtocolAccess` preserves the declaring policy's authority but does not prove that the policy belongs to the client's configured access-grant principal. Effective read and provisioning relationships are derived only after that principal resolves to an enabled entity and its effective ACLs are evaluated. Provisioning reaches an observed client-owned resource directly; collection creation and unresolved targets remain potential access anchored to the client.

### Properties

| Node/Edge Type | Property | Description |
| --- | --- | --- |
| `Vault_ScimClient` | `Client Name` | Stores the configured SCIM client name. |
| `Vault_ScimClient` | `Client ID` | Identifies the SCIM client and correlates client-owned resources. |
| `Vault_ScimClient` | `Access Grant Principal` | Identifies the entity authorized to use the client. |
| `Vault_ScimClient` | `Alias Mount Accessor` | Identifies the auth mount used to correlate SCIM-created aliases. |
| `Vault_ScimClient` | `Deleting` | Indicates that client deletion is in progress. |
| `Vault_ScimProtocolAccess` | `SCIM Targets` | Identifies Users, Groups, or discovery collections authorized by the policy. |
| `Vault_ScimProtocolAccess` | `Surfaces` | Lists the authenticated SCIM protocol surfaces matched by the ACL. |
| `Vault_ScimProtocolAccess` | `Operations` | Lists the allowed SCIM protocol operations. |
| `Vault_ScimProtocolAccess` | `Client Names` | Lists SCIM clients to which the declared policy access applies. |
| `Vault_ScimProtocolAccess` | `Access Grant Principals` | Lists principals that must own the effective ACL for client use. |
| `Vault_ScimProtocolAccess` | `Principal Match Required` | Indicates that policy access alone is insufficient without the configured principal match. |
| `Vault_ScimReadResources`<br>`Vault_ScimProvisionResources`<br>`Vault_PotentialAccess` | `Client Names` | Lists the SCIM clients through which resource access is evaluated. |
| `Vault_ScimReadResources`<br>`Vault_ScimProvisionResources`<br>`Vault_PotentialAccess` | `SCIM Client IDs` | Lists client identifiers used to prove resource ownership. |
| `Vault_ScimReadResources`<br>`Vault_ScimProvisionResources`<br>`Vault_PotentialAccess` | `Scopes` | Distinguishes exact resource access from patterned collection access. |
| `Vault_ScimReadResources`<br>`Vault_ScimProvisionResources`<br>`Vault_PotentialAccess` | `Operations` | Lists the effective SCIM read or mutation operations. |
| `Vault_ScimProvisionResources` | `Target Resource Observed` | Indicates that the edge reaches a concrete resource owned by the client. |
| `Vault_PotentialAccess` | `Potential Outcomes` | Describes unobserved SCIM resource creation or unresolved provisioning. |
| `Vault_PotentialAccess` | `Requirements` | Lists unresolved ownership, selector, or target prerequisites. |
| `Vault_PotentialAccess` | `Resolution Status` | Explains why concrete resource access could not be proven. |

### Attack Paths

SCIM read, protocol, provisioning, ownership, and principal relationships are currently non-traversable evidence. `Vault_ScimManages` describes configured ownership but is not used as a containment fan-out or attack-path hop. This prevents read-only, collection-level, or unresolved SCIM access from implying control of every entity and group.

## Template Policies

Identity templates can reference entity fields, an entity alias on a specific accessor, or an identity group by ID. The rendered effective edge originates from the referenced identity representation:

```mermaid
flowchart LR
    source[Vault_Entity, Vault_EntityAlias, or Vault_Group]:::identityNode -->|Vault_KvReadSecret| target[Vault_KvFile]:::objectNode

    classDef identityNode fill:#2F80ED,color:#fff,stroke:#1B4F72,stroke-width:2px
    classDef objectNode fill:#D35400,color:#fff,stroke:#873600,stroke-width:2px
```

Equivalent Cypher query:

```cypher
MATCH p = (source)-[r:Vault_KvReadSecret]->(target:Vault_KvFile)
WHERE r.templated = true
  AND (source:Vault_Entity OR source:Vault_EntityAlias OR source:Vault_Group)
RETURN p
```

The KV read is a concrete example. Template resolution can emit any compatible destination subsystem edge while retaining the same provenance properties.

### Nodes

Template resolution introduces no template-specific node kind. It uses an observed `Vault_Entity`, `Vault_EntityAlias`, or `Vault_Group` as the effective source and a concrete node from the destination subsystem as the target.

### Edges

Template resolution introduces no template-only edge kind. The collector emits the destination subsystem's ordinary operation edge and marks it with template and policy-provenance properties.

| Template reference | Effective source |
| --- | --- |
| `identity.entity.*` | `Vault_Entity` |
| `identity.entity.aliases.<accessor>.*` | Matching `Vault_EntityAlias` |
| `identity.groups.ids.<group-id>.*` | Referenced `Vault_Group` |

Policy inheritance from a group remains provenance on the edge. It does not make the group the source unless the template expression itself references that group.

### Properties

Rendered template relationships use the destination subsystem's normal edge kind and properties. They additionally carry the common template provenance documented in [MODEL.md](../MODEL.md#identity-templates-and-provenance). There is no separate template-only relationship family.

| Node/Edge Type | Property | Description |
| --- | --- | --- |
| Template-resolved access edges | `Templated` | Indicates that an Identity template was rendered to produce the effective edge. |
| Template-resolved access edges | `Template Entity Fields` | Lists entity, alias, or group fields referenced by the template. |
| Template-resolved access edges | `Resolved For Entity IDs` | Lists canonical entities whose context was used during rendering. |
| Template-resolved access edges | `Resolved Source Types` | Identifies whether the effective source is an entity, entity alias, or group. |
| Template-resolved access edges | `Matched Policy Paths` | Preserves the original unrendered HCL template paths. |
| Template-resolved access edges | `Matched Paths` | Lists concrete paths produced after template rendering. |
| Template-resolved access edges | `Via Policies` | Lists policies that contributed the effective templated permission. |

### Attack Paths

A rendered template edge can originate directly from the referenced entity representation and reach a concrete subsystem target. The destination subsystem documents the resulting security edge, such as `Vault_KvReadSecret` in the [KV section](MOUNTS.md#kv). `Matched Policy Paths`, rendered `Matched Paths`, and `Via Policies` preserve why the effective identity-specific edge exists.
