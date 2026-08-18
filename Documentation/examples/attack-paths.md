# Attack-Path Examples

These examples illustrate graph meaning. Node names and policy contents are representative.

## Group-Inherited KV Read

```text
USERPASS USER
  -> Vault_MapsTo
ENTITY ALIAS
  -> Vault_MapsTo
ENTITY
  -> Vault_MemberOf
GROUP
  -> Vault_LinksPolicy
POLICY
  -> Vault_KvReadSecret
KV FILE
  -> Vault_Contains
KV PAIR
```

Interpretation: the login identity resolves to an entity, the entity inherits a policy through group membership, and the policy can read plaintext from the observed KV file. The pair node records a key name, not the value.

## Identity-Templated KV Read

Policy:

```hcl
path "kv/data/dept/{{identity.entity.metadata.department}}/*" {
  capabilities = ["read"]
}
```

For an entity with `department=engineering`, the collector renders the concrete path and emits an effective edge from that entity to matching observed KV files. Properties retain both the rendered path and original template, plus the contributing policy.

The alias does not also receive the edge unless the template references alias fields. A group does not become the source merely because it supplied the policy.

## UserPass Password Reset

```text
POLICY A
  -> Vault_ControlObject
USERPASS USER
  -> Vault_MapsTo
ENTITY
  -> Vault_LinksPolicy
POLICY B
```

The control edge is derived only when Policy A can set an attacker-controlled password for the concrete user. This is stronger than ordinary `Vault_ManageObject` and supports an attack path into the user's identity and policies.

## Policy Acquisition Through Group Membership

```text
POLICY A
  -> Vault_ControlObject
INTERNAL GROUP
  -> Vault_LinksPolicy
POLICY B
```

If Policy A can add a controlled entity to the group without restrictive parameter constraints, it can inherit Policy B. `Vault_ObtainPolicy` may summarize the proven composition directly from Policy A to Policy B with the group recorded as the via object.

## AppRole SecretID

```text
POLICY
  -> Vault_AuthApproleGenerateSecretId
APPROLE ROLE
  -> Vault_LinksPolicy
ROLE POLICY
```

The edge is traversable only when RoleID is already known or the source can read it. If RoleID is unavailable, SecretID generation becomes `Vault_PotentialAccess`.

## Dynamic Cloud Credentials

```text
POLICY
  -> Vault_GenerateCredentials
AWS ROLE
```

The role properties and edge describe whether Vault returns an IAM user, assumed role, federation token, or session token. An MFA-only session-token role remains potential unless the required MFA input is proven available.

The edge proves the ability to request credentials from Vault, not the complete downstream AWS permission set. A future AWS collector can correlate role ARNs, policies, and generated-principal characteristics.

## Database Connection Prerequisite

```text
POLICY
  -> Vault_GenerateCredentials
DATABASE ROLE
  -> Vault_References
DATABASE CONNECTION
```

The generation edge is traversable only when the referenced connection is observed, compatible, and permits the role through `allowed_roles`. Incomplete connection collection produces potential access instead of a false path.

## Transit Decrypt

```text
POLICY
  -> Vault_TransitDecrypt
TRANSIT KEY
```

This represents a plaintext oracle using the concrete key. Encrypt and verify edges are non-traversable because they do not reveal plaintext or grant signing authority.

## Transit Export

```text
POLICY
  -> Vault_TransitExportKey
TRANSIT KEY
```

This edge exists only when the observed key type supports the requested secret export and the key is exportable. Reading a public key uses `Vault_ReadObject`; BYOK-wrapped export uses non-traversable `Vault_TransitExportByokKey`.

## PKI Role Glob

Policy:

```hcl
path "pki/issue/*" {
  capabilities = ["create", "update"]
}
```

The collector emits `Vault_PkiIssueCertificate` to every observed compatible PKI role. It does not emit one traversable edge to the PKI mount, because mount containment would imply authority over issuers and keys unrelated to certificate issuance.

## Synthetic Target

Policy:

```hcl
path "transit/decrypt/future-key" {
  capabilities = ["update"]
}
```

If `future-key` was not observed, the collector can represent the exact synthetic key but converts the decrypt outcome to `Vault_PotentialAccess` with `Target Observed: false`. It does not attach the synthetic key through normal containment.

## Destructive but Non-Traversable

```text
POLICY
  -> Vault_ManageObject
PKI ISSUER
```

Delete or revoke permission can be operationally severe without granting the issuer's signing authority. Such an edge is intentionally excluded from automatic attack paths.
