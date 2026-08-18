# Coverage Matrix

This document describes first-class collector coverage. It is not a claim that every Vault edition, plugin version, or public protocol endpoint can be observed with every collector token.

## Platform and Identity

| Area | Nodes | Principal relationships | ACL modeling | Notes |
| --- | --- | --- | --- | --- |
| Server and namespaces | Server, Namespace, Store | Contains, ParentOf | Store-scoped config and object operations | One namespace context is collected per run. |
| Policies | Policy, policy Store | LinksPolicy | HCL capabilities, wildcards, templates, parameter constraints | ACL policies are the primary modeled policy type. |
| Identity | Entity, Entity Alias, Group, Group Alias | MapsTo, MemberOf, LinksPolicy | Read, manage, control, policy acquisition | Direct and inherited group relationships are distinguished in properties. |
| OIDC provider | Provider, Application, Assignment, Scope, Key, Token Role | OIDC assignment and provider relationships | Read/manage, authorization, token generation, credential reads | Outbound OIDC where Vault acts as provider. |
| MFA | MFA Method, Login Enforcement | UsesMethod, AppliesTo | Read/manage, self-enroll, secret generation | MFA is also modeled as a prerequisite rather than a login edge. |
| SCIM | SCIM Client, owned Entity and Group | UsesPrincipal, Manages | Protocol read/provision evidence | Ownership and access-grant principal are required for effective SCIM edges. |
| Managed keys | Managed Key | ManagedBy, CanUseManagedKey | List/read/manage key operations | Enterprise external KMS/HSM-backed keys. |

## Supported Auth Methods

| Auth Method | Mount config | Child objects | Policy grants | Specialized operations |
| --- | --- | --- | --- | --- |
| AliCloud | Yes | Roles | Yes | Login constraints and role management. |
| AppRole | Yes | Roles | Yes | RoleID visibility, SecretID generation and destruction. |
| AWS | Yes | Roles | Yes | Role tags and AWS-specific login constraints. |
| Azure | Yes | Roles | Yes | Azure identity-bound role configuration. |
| Cloud Foundry | Yes | Roles | Yes | CF certificate and organization/space constraints. |
| GitHub | Yes | Users, teams | Yes | User/team mappings and organization configuration. |
| GCP | Yes | Roles | Yes | IAM/GCE role types and bound service identities. |
| JWT/OIDC | Yes | Roles | Yes | JWT/OIDC trust, claims, audiences, redirect URIs, role modes. |
| Kerberos | Yes | Groups | Yes | LDAP/Kerberos config and generated group aliases. |
| Kubernetes | Yes | Roles | Yes | Service account, namespace, audience, and token-review trust. |
| LDAP | Yes | Users, groups | Yes | User/group mappings, LDAP config, root rotation. |
| OCI | Yes | Roles | Yes | OCI group and dynamic-group constraints. |
| Okta | Yes | Users, groups | Yes | User/group mappings and Okta API configuration. |
| RADIUS | Yes | Users | Yes | User policy mappings and RADIUS configuration. |
| SAML | Yes | Roles | Yes | Assertion trust, subjects, attributes, and default role. |
| SCEP | Yes | Roles | Yes | Static-challenge and Intune enrollment authentication. |
| SPIFFE | Yes | Roles | Yes | JWT/X.509 SVID trust, workload patterns, alias matching. |
| TLS Certificate | Yes | Certificate roles, CRLs | Yes | Trusted certificates, constraints, and CRL management. |
| Token | Yes | Token roles | Yes | Lookup, accessor listing, restricted/privileged creation, renewal/revocation. |
| UserPass | Yes | Users | Yes | User creation, password/policy management, alias correlation. |

See [auth-methods/README.md](auth-methods/README.md) for endpoint and edge behavior.

## Supported Secrets Engines

| Engine | Mount config | Child objects | Specialized access outcomes |
| --- | --- | --- | --- |
| AWS | Root/lease configuration | Dynamic roles, static roles | Generate IAM/STS credentials; read static credentials. |
| Azure | Engine configuration | Dynamic roles, static roles | Generate service-principal credentials; read/import static credentials. |
| Database | Engine configuration | Connections, dynamic roles, static roles | Generate database credentials; read static credentials; reset/reload connections. |
| GCP | Engine configuration | Rolesets, static accounts, impersonated accounts | Generate OAuth tokens or service-account keys; read static credentials. |
| GCP KMS | Engine configuration | KMS key registrations | Encrypt, decrypt, re-encrypt, sign, verify with purpose checks. |
| Kubernetes | Cluster configuration | Roles | Generate service-account credentials with namespace and binding constraints. |
| KV | KV v1/v2 configuration | Directories, files, top-level key names | Read secret, manage secret, read/manage metadata, lifecycle and CAS context. |
| LDAP | Engine configuration | Dynamic roles, static roles, library sets, service accounts | Generate/read credentials; checkout/checkin service accounts. |
| PKI | CA and protocol configuration | Roles, issuers, keys | Issue/sign certificates, issuer/root/intermediate lifecycle, ACME/CMP/EST/SCEP policy surfaces. |
| SSH | CA and zero-address configuration | Roles | Generate OTP, sign key, issue key pair, lookup roles. |
| Terraform Cloud | Engine configuration | Roles | Generate Terraform Cloud tokens. |
| TOTP | Engine configuration | TOTP keys | Generate and validate TOTP codes. |
| Transit | Engine configuration | Transit keys | Encrypt/decrypt, datakey, rewrap, sign, MAC, verify, export. |

See [secrets-engines/README.md](secrets-engines/README.md) for resource and policy mappings.

## Unsupported Secrets Engines

Any mounted secrets engine outside the supported set is emitted as a generic `Vault_SecretsEngine` with its path and Vault-reported type. VaultHound does not collect child resources or derive first-class access edges for it.

This avoids silently applying generic `read` or `manage` semantics to a plugin whose endpoint behavior is unknown.

## Edition and Version Dependencies

Some modeled features require Vault Enterprise or a sufficiently recent Vault version, including namespaces, managed keys, SCIM, MFA variants, static credential engines, and PKI issuance protocols. If an endpoint is unavailable, the corresponding objects and edges are absent.

The collector does not currently emit a separate completeness node. Use logs and collector-token permissions to distinguish absence from lack of visibility.

## Public and Protocol Endpoints

Public PKI authority-information endpoints and unauthenticated protocol flows are not treated as ACL-derived policy rights. Authenticated management and credential-generation endpoints are modeled where they have security relevance.

ACME, CMP, EST, and SCEP configuration and authenticated enrollment surfaces are represented, but external protocol state such as an ACME challenge result or external IdP account control may remain a runtime prerequisite.

## Known Limitations

- Collection is scoped to one Vault address and namespace context per invocation.
- External cloud, directory, database, Kubernetes, and Terraform resources are not independently ingested, so downstream resource authority is summarized from Vault configuration.
- A missing object may reflect insufficient collection permission.
- Policy parameter constraints are modeled from HCL but cannot predict arbitrary plugin-side validation.
- Dynamic credentials, tokens, OTPs, certificates, and decrypted plaintext are not generated during collection.
- KV nested values are not collected; only top-level key names are represented.
- Runtime availability, leases, quotas, control groups, Sentinel outcomes, and response wrapping can add constraints not fully represented by a static graph.
