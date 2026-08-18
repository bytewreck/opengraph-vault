# Traversability and Offensive Semantics

## Definition

In VaultHound, `is_traversable: true` means that control or use of the source can defensibly produce the security outcome represented by the target. It does not simply mean that Vault authorizes an API request.

A non-traversable edge can still represent dangerous administration, destructive access, or sensitive visibility. It is excluded from automatic attack paths because the operation does not prove that the attacker obtains the target's authority.

## Threat Model

The model assumes that an attacker can exercise the capabilities of a reached policy or principal. A traversable edge should therefore satisfy all of the following:

1. The target is concrete and observed, or uncertainty is explicitly represented.
2. Required Vault capabilities are present for the exact endpoint.
3. Known endpoint prerequisites are satisfied.
4. The outcome grants usable authority, credential material, cryptographic ability, or identity control.
5. Traversing onward from the target does not imply materially broader control than the operation provides.

## Why Containment Is Traversable

`Vault_Contains` is traversable because the model treats control of a parent administrative structure as control of its immediate children. This is intentionally powerful, so edges entering containers must be conservative.

Ordinary `Vault_ManageConfig`, `Vault_ManageObject`, and `Vault_CreateObject` relationships are non-traversable. A narrowly scoped operation must not reach an entire mount and then inherit control of all children through containment.

## Traversable Relationship Families

The exact registered list is generated in [SCHEMA.md](SCHEMA.md). The current families are:

### Hierarchy and Authority

- `Vault_Contains`
- `Vault_ParentOf`
- `Vault_MemberOf`
- `Vault_MapsTo`
- `Vault_LinksPolicy`

These relationships model inheritance or identity resolution. They should be used only where the target's authority genuinely follows from the source.

### Identity and Policy Escalation

- `Vault_ReadCredential` exposes returned credential material from a concrete object.
- `Vault_GenerateIdentityToken` produces an identity token through an allowed signing role.
- `Vault_OidcAuthenticateTo` represents proven access to an OIDC application through assignment and provider constraints.
- `Vault_ControlObject` represents a proven takeover-capable mutation.
- `Vault_ObtainPolicy` composes object control with assignable policy authority.

`Vault_ControlObject` is deliberately narrower than `Vault_ManageObject`. Examples include resetting a UserPass password, adding a controlled identity to an internal group, rebinding an alias under attacker control, or replacing authentication trust without restrictive parameter constraints.

### Credential Acquisition

- `Vault_GenerateCredentials` covers viable dynamic credential generation.
- `Vault_ReadStaticCredentials` covers reading a concrete managed static credential.
- `Vault_AuthApproleGenerateSecretId` requires a usable RoleID path in addition to SecretID generation.
- `Vault_AuthTokenCreatePrivilegedToken` requires demonstrated policy expansion or another privileged issuance mode.
- `Vault_LdapCheckoutServiceAccount` targets only observed currently available service accounts.
- `Vault_SshGenerateOtp` and `Vault_SshIssueKeyPair` return usable authentication material.
- `Vault_TotpGenerateCode` returns a current TOTP code.

Restricted token creation is non-traversable because it cannot normally grant more authority than the caller already has.

### Secret and Cryptographic Outcomes

- `Vault_KvReadSecret` returns KV plaintext from a concrete file.
- `Vault_GcpKmsDecrypt` and `Vault_GcpKmsSign` require a compatible observed key purpose.
- PKI issue and sign edges represent certificate or CA-signing authority against concrete roles or issuers.
- `Vault_SshSignKey` represents SSH certificate signing through a concrete role.
- Transit decrypt, sign, CMAC, HMAC, and secret-key export edges represent usable cryptographic outcomes.

Transit public-material reads and BYOK-wrapped exports are non-traversable because they do not expose the raw secret key. `Vault_TransitExportKey` is emitted only for a compatible observed key with `exportable` enabled.

## Non-Traversable Relationship Families

The following are non-traversable by default:

- Listing and ordinary object reads.
- Configuration reads and writes.
- Creation of unobserved objects.
- Deletion, revocation, rotation, tidy, and maintenance operations.
- Encryption, rewrap, and verification operations that do not reveal plaintext or signing authority.
- Metadata and KV lifecycle management.
- OIDC, MFA, SCIM, and auth-method configuration references.
- Potential access with unresolved target or prerequisite.

These edges remain valuable for investigation and can be included explicitly in analytical queries.

## Safeguards

### Synthetic Targets

An exact policy path may name an object the collector cannot observe. A security-outcome edge to that synthetic object is converted to `Vault_PotentialAccess` with `Target Observed: false`.

### Runtime Selection

Mount-level PKI operations, wildcard creation, and other runtime-selected targets do not become traversable merely because the mount contains sensitive children. Concrete observed targets are expanded where possible; unresolved outcomes remain potential.

### Compatibility

The collector checks key type, purpose, exportability, role mode, referenced connection, allowed-role constraints, CAS requirements, MFA requirements, RoleID availability, and service-account availability where those facts are observable.

### Parameter Constraints

HCL `allowed_parameters`, `denied_parameters`, and `required_parameters` are preserved and used when deriving takeover relationships. A management capability with constrained attacker-controlled values may produce `Vault_PotentialAccess` instead of `Vault_ControlObject`.

### Public Endpoints

Unauthenticated PKI and protocol endpoints are not modeled as policy-derived attack paths. Their existence may still be represented through configuration or resource properties.

## Interpreting Paths

Consider:

```text
Auth User -> MapsTo -> Entity -> MemberOf -> Group -> LinksPolicy -> Policy
           -> KvReadSecret -> KV File -> Contains -> KV Pair
```

This means the auth user resolves to an active entity, inherits a policy through the group, and that policy can read the observed KV secret. The final containment hop exposes only the names of keys present in that secret; VaultHound does not store their values.

By contrast:

```text
Policy -> ManageConfig -> Transit Mount
```

is not an attack path. The policy can administer some mount configuration, but that does not automatically imply control of every Transit key beneath the mount.

## Known Conservative Areas

- ACME EAB creation returns registration credential material, but remains non-traversable because challenge completion and directory-specific registration are additional prerequisites.
- Creation edges for unobserved objects remain non-traversable or potential even when a future object could become exploitable.
- External cloud and database permissions are modeled from Vault configuration. VaultHound cannot always prove the downstream cloud principal's live state or external authorization.

## Review Checklist

When adding or changing an edge, verify:

1. Does the endpoint return a credential, plaintext, signature, token, or authenticated session?
2. Does the target represent the exact affected object?
3. Would traversable containment from that target overstate the result?
4. Are object type, key purpose, role mode, and endpoint prerequisites known?
5. What happens for a glob, an exact missing object, a deny rule, and a template?
6. Are create, update, patch, delete, recover, and sudo treated according to the endpoint rather than generically?
7. Is a destructive effect being confused with takeover?
8. Are focused tests present for both the traversable and potential/non-traversable cases?
