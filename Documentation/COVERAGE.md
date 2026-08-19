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
| --- | :---: | --- | :---: | --- |
| AliCloud | :white_check_mark: | Roles | :white_check_mark: | Login constraints and role management. |
| AppRole | :white_check_mark: | Roles | :white_check_mark: | RoleID visibility, SecretID generation and destruction. |
| AWS | :white_check_mark: | Roles | :white_check_mark: | Role tags and AWS-specific login constraints. |
| Azure | :white_check_mark: | Roles | :white_check_mark: | Azure identity-bound role configuration. |
| Cloud Foundry | :white_check_mark: | Roles | :white_check_mark: | CF certificate and organization/space constraints. |
| GitHub | :white_check_mark: | Users, teams | :white_check_mark: | User/team mappings and organization configuration. |
| GCP | :white_check_mark: | Roles | :white_check_mark: | IAM/GCE role types and bound service identities. |
| JWT/OIDC | :white_check_mark: | Roles | :white_check_mark: | JWT/OIDC trust, claims, audiences, redirect URIs, role modes. |
| Kerberos | :white_check_mark: | Groups | :white_check_mark: | LDAP/Kerberos config and generated group aliases. |
| Kubernetes | :white_check_mark: | Roles | :white_check_mark: | Service account, namespace, audience, and token-review trust. |
| LDAP | :white_check_mark: | Users, groups | :white_check_mark: | User/group mappings, LDAP config, root rotation. |
| OCI | :white_check_mark: | Roles | :white_check_mark: | OCI group and dynamic-group constraints. |
| Okta | :white_check_mark: | Users, groups | :white_check_mark: | User/group mappings and Okta API configuration. |
| RADIUS | :white_check_mark: | Users | :white_check_mark: | User policy mappings and RADIUS configuration. |
| SAML | :white_check_mark: | Roles | :white_check_mark: | Assertion trust, subjects, attributes, and default role. |
| SCEP | :white_check_mark: | Roles | :white_check_mark: | Static-challenge and Intune enrollment authentication. |
| SPIFFE | :white_check_mark: | Roles | :white_check_mark: | JWT/X.509 SVID trust, workload patterns, alias matching. |
| TLS Certificate | :white_check_mark: | Certificate roles, CRLs | :white_check_mark: | Trusted certificates, constraints, and CRL management. |
| Token | :white_check_mark: | Token roles | :white_check_mark: | Lookup, accessor listing, restricted/privileged creation, renewal/revocation. |
| UserPass | :white_check_mark: | Users | :white_check_mark: | User creation, password/policy management, alias correlation. |

See the [Auth Store guide](stores/AUTH.md) for endpoint, property, and edge behavior.

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

See the [Mount Store guide](stores/MOUNTS.md) for resource, property, and policy mappings.

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
