#!/usr/bin/env python3
"""Generate Documentation/SCHEMA.md from the registered OpenGraph schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schema.json"
OUTPUT_PATH = ROOT / "Documentation" / "SCHEMA.md"


STRUCTURAL_EDGES = {
    "Vault_Contains",
    "Vault_References",
    "Vault_ParentOf",
    "Vault_MemberOf",
    "Vault_MapsTo",
    "Vault_LinksPolicy",
    "Vault_OnAuthMethod",
    "Vault_ManagedBy",
    "Vault_CanUseManagedKey",
    "Vault_OidcAllowsApplication",
    "Vault_OidcGrantsAccess",
    "Vault_OidcSupportsScope",
    "Vault_OidcAssignedTo",
    "Vault_MfaUsesMethod",
    "Vault_MfaAppliesTo",
    "Vault_ScimUsesPrincipal",
    "Vault_ScimManages",
    "Vault_AuthSamlDefaultRole",
    "Vault_AuthSpiffeMayMatchRole",
    "Vault_DatabaseUsesConnection",
}


EDGE_ENDPOINTS = {
    "Vault_Contains": ("Vault container or parent object", "Immediate observed child object"),
    "Vault_References": ("Resolved Vault object", "Referenced Vault object"),
    "Vault_ParentOf": ("Vault_Namespace", "Child Vault_Namespace"),
    "Vault_MemberOf": ("Vault_Entity, Vault_Group, or auth principal", "Vault_Group or auth group"),
    "Vault_MapsTo": ("Auth or alias representation", "Canonical alias, entity, or group"),
    "Vault_LinksPolicy": ("Identity, group, auth role, or auth principal", "Vault_Policy"),
    "Vault_DenyAccess": ("Vault_Policy", "Matched Vault object or subsystem anchor"),
    "Vault_PotentialAccess": ("Vault_Policy or resolved principal", "Unresolved, runtime-selected, or synthetic target"),
    "Vault_OnAuthMethod": ("Vault_EntityAlias or Vault_GroupAlias", "Vault_AuthMethod"),
    "Vault_ManagedBy": ("Vault key object", "Vault_ManagedKey"),
    "Vault_CanUseManagedKey": ("Vault_Policy", "Vault_ManagedKey"),
    "Vault_ReadIdentity": ("Vault_Policy or resolved entity", "Identity store or concrete identity object"),
    "Vault_ReadCredential": ("Vault_Policy or resolved entity", "Concrete object returning credential material"),
    "Vault_GenerateIdentityToken": ("Vault_Policy or resolved entity", "Vault_OidcTokenRole"),
    "Vault_OidcAllowsApplication": ("Vault_OidcProvider", "Vault_OidcApplication"),
    "Vault_OidcGrantsAccess": ("Vault_OidcAssignment", "Vault_OidcApplication"),
    "Vault_OidcSupportsScope": ("Vault_OidcProvider", "Vault_OidcScope"),
    "Vault_OidcAssignedTo": ("Vault_Entity or Vault_Group", "Vault_OidcAssignment"),
    "Vault_OidcAuthorize": ("Vault_Policy", "Vault_OidcProvider"),
    "Vault_OidcAuthenticateTo": ("Vault_Entity", "Vault_OidcApplication"),
    "Vault_MfaUsesMethod": ("Vault_MfaLoginEnforcement", "Vault_MfaMethod"),
    "Vault_MfaAppliesTo": ("Vault_MfaLoginEnforcement", "Identity or auth object"),
    "Vault_MfaSelfEnroll": ("Vault_Policy or resolved entity", "Vault_MfaMethod"),
    "Vault_MfaGenerateSecret": ("Vault_Policy or resolved entity", "Vault_MfaMethod"),
    "Vault_ScimUsesPrincipal": ("Vault_ScimClient", "Vault_Entity"),
    "Vault_ScimProtocolAccess": ("Vault_Policy", "Vault_ScimClient"),
    "Vault_ScimManages": ("Vault_ScimClient", "SCIM-owned Vault_Entity or Vault_Group"),
    "Vault_ScimReadResources": ("SCIM access-grant Vault_Entity", "Vault_ScimClient"),
    "Vault_ScimProvisionResources": ("SCIM access-grant Vault_Entity", "Observed SCIM-owned entity or group"),
    "Vault_ListObjects": ("Vault_Policy", "Store, mount, collection, or directory"),
    "Vault_CreateObject": ("Vault_Policy", "Store, mount, collection, or exact synthetic object"),
    "Vault_ReadObject": ("Vault_Policy", "Concrete durable Vault object"),
    "Vault_ManageObject": ("Vault_Policy", "Concrete durable Vault object"),
    "Vault_ControlObject": ("Vault_Policy or resolved principal", "Concrete security-bearing object"),
    "Vault_ReadConfig": ("Vault_Policy", "Store, auth method, secrets engine, or config object"),
    "Vault_ManageConfig": ("Vault_Policy", "Store, auth method, secrets engine, or config object"),
    "Vault_GenerateCredentials": ("Vault_Policy", "Observed secrets-engine role or account"),
    "Vault_ReadStaticCredentials": ("Vault_Policy", "Observed static role or account"),
    "Vault_AuthApproleReadSecretId": ("Vault_Policy", "Vault_AuthApproleRole"),
    "Vault_AuthApproleGenerateSecretId": ("Vault_Policy", "Vault_AuthApproleRole"),
    "Vault_AuthApproleManageSecretId": ("Vault_Policy", "Vault_AuthApproleRole"),
    "Vault_AuthAwsCreateRoleTag": ("Vault_Policy", "Vault_AuthAwsRole or AWS auth mount"),
    "Vault_AuthSamlDefaultRole": ("Vault_AuthMethodSaml", "Vault_AuthSamlRole"),
    "Vault_AuthSpiffeMayMatchRole": ("Vault_EntityAlias", "Vault_AuthSpiffeRole"),
    "Vault_AuthTokenReadToken": ("Vault_Policy", "Vault_AuthMethodToken"),
    "Vault_AuthTokenCreateRestrictedToken": ("Vault_Policy", "Vault_AuthMethodToken or Vault_AuthTokenRole"),
    "Vault_AuthTokenCreatePrivilegedToken": ("Vault_Policy", "Policy store or Vault_AuthTokenRole"),
    "Vault_AuthTokenManageToken": ("Vault_Policy", "Vault_AuthMethodToken"),
    "Vault_AuthTokenListAccessors": ("Vault_Policy", "Vault_AuthMethodToken"),
    "Vault_AzureImportStaticRole": ("Vault_Policy", "Vault_AzureStaticRole or Azure mount"),
    "Vault_DatabaseUsesConnection": ("Vault_DatabaseRole or Vault_DatabaseStaticRole", "Vault_DatabaseConnection"),
    "Vault_DatabaseResetConnection": ("Vault_Policy", "Vault_DatabaseConnection or Database mount"),
    "Vault_DatabaseReloadPlugin": ("Vault_Policy", "Vault_DatabaseConnection or Database mount"),
    "Vault_GcpKmsEncrypt": ("Vault_Policy", "Vault_GcpKmsKey"),
    "Vault_GcpKmsDecrypt": ("Vault_Policy", "Vault_GcpKmsKey"),
    "Vault_GcpKmsReencrypt": ("Vault_Policy", "Vault_GcpKmsKey"),
    "Vault_GcpKmsSign": ("Vault_Policy", "Vault_GcpKmsKey"),
    "Vault_GcpKmsVerify": ("Vault_Policy", "Vault_GcpKmsKey"),
    "Vault_KvReadSecret": ("Vault_Policy or resolved entity", "Vault_KvFile"),
    "Vault_KvManageSecret": ("Vault_Policy or resolved entity", "Vault_KvFile"),
    "Vault_KvReadMetadata": ("Vault_Policy or resolved entity", "Vault_KvFile"),
    "Vault_KvManageMetadata": ("Vault_Policy or resolved entity", "Vault_KvFile"),
    "Vault_LdapReadLibraryStatus": ("Vault_Policy", "Vault_LdapLibrarySet or service account"),
    "Vault_LdapCheckoutServiceAccount": ("Vault_Policy", "Available Vault_LdapServiceAccount"),
    "Vault_LdapCheckinServiceAccount": ("Vault_Policy", "Vault_LdapLibrarySet or service account"),
    "Vault_LdapForceCheckinServiceAccount": ("Vault_Policy", "Vault_LdapLibrarySet or service account"),
    "Vault_PkiListCertificateInfo": ("Vault_Policy", "Vault_SecretsEnginePki"),
    "Vault_PkiIssueCertificate": ("Vault_Policy", "Vault_PkiRole"),
    "Vault_PkiSignCertificate": ("Vault_Policy", "Vault_PkiRole"),
    "Vault_PkiSignVerbatim": ("Vault_Policy", "Vault_PkiRole or Vault_PkiIssuer"),
    "Vault_PkiSignIntermediate": ("Vault_Policy", "Vault_PkiIssuer"),
    "Vault_PkiSignSelfIssued": ("Vault_Policy", "Vault_PkiIssuer"),
    "Vault_PkiRevokeCertificate": ("Vault_Policy", "Vault_SecretsEnginePki or Vault_PkiIssuer"),
    "Vault_PkiRevokeIssuer": ("Vault_Policy", "Vault_PkiIssuer"),
    "Vault_PkiProvisionIssuer": ("Vault_Policy", "Vault_SecretsEnginePki"),
    "Vault_PkiManageRoot": ("Vault_Policy", "Vault_SecretsEnginePki"),
    "Vault_PkiDeleteRoot": ("Vault_Policy", "Vault_SecretsEnginePki"),
    "Vault_PkiManageIntermediate": ("Vault_Policy", "Vault_SecretsEnginePki"),
    "Vault_PkiAcmeCreateEab": ("Vault_Policy", "PKI mount, issuer, or role ACME surface"),
    "Vault_PkiAcmeManageAccounts": ("Vault_Policy", "Vault_SecretsEnginePki"),
    "Vault_SshGenerateOtp": ("Vault_Policy", "Vault_SshRole"),
    "Vault_SshLookupRoles": ("Vault_Policy", "Vault_SecretsEngineSsh"),
    "Vault_SshSignKey": ("Vault_Policy", "Vault_SshRole"),
    "Vault_SshIssueKeyPair": ("Vault_Policy", "Vault_SshRole"),
    "Vault_TotpGenerateCode": ("Vault_Policy", "Vault_TotpKey"),
    "Vault_TotpValidateCode": ("Vault_Policy", "Vault_TotpKey"),
    "Vault_TransitEncrypt": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitDecrypt": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitGenerateDataKey": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitRewrap": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitSign": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitGenerateCmac": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitGenerateHmac": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitVerify": ("Vault_Policy", "Vault_TransitKey"),
    "Vault_TransitExportKey": ("Vault_Policy", "Exportable Vault_TransitKey"),
    "Vault_TransitExportByokKey": ("Vault_Policy", "Vault_TransitKey"),
}


def escape(value: object) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def relationship_table(edges: list[dict]) -> list[str]:
    lines = [
        "| Edge Type | Typical Sources | Typical Destinations | Traversable | Description |",
        "| --- | --- | --- | --- | --- |",
    ]
    for edge in edges:
        source, destination = EDGE_ENDPOINTS[edge["name"]]
        lines.append(
            f"| `{edge['name']}` | {escape(source)} | {escape(destination)} | "
            f"`{str(bool(edge.get('is_traversable'))).lower()}` | {escape(edge.get('description'))} |"
        )
    return lines


def render(schema: dict) -> str:
    nodes = schema["node_kinds"]
    edges = schema["relationship_kinds"]
    edge_names = {edge["name"] for edge in edges}
    missing = sorted(edge_names - EDGE_ENDPOINTS.keys())
    stale = sorted(EDGE_ENDPOINTS.keys() - edge_names)
    if missing or stale:
        raise ValueError(f"relationship endpoint catalog mismatch; missing={missing}, stale={stale}")

    traversable_count = sum(bool(edge.get("is_traversable")) for edge in edges)
    structural = [edge for edge in edges if edge["name"] in STRUCTURAL_EDGES]
    access = [edge for edge in edges if edge["name"] not in STRUCTURAL_EDGES]
    metadata = schema["schema"]

    lines = [
        "# VaultHound OpenGraph Schema Reference",
        "",
        "> Generated by `Documentation/tools/generate_schema_reference.py` from `schema.json`. Do not edit this file manually.",
        "",
        f"- Schema: `{metadata['name']}` (`{metadata['version']}`)",
        f"- Namespace prefix: `{metadata['namespace']}_`",
        f"- Node kinds: `{len(nodes)}`",
        f"- Relationship kinds: `{len(edges)}`",
        f"- Traversable relationships: `{traversable_count}`",
        f"- Non-traversable relationships: `{len(edges) - traversable_count}`",
        "",
        "For interpretation, collection provenance, and offensive semantics, read "
        "[MODEL.md](MODEL.md), [COLLECTION.md](COLLECTION.md), and the "
        "[store guides](README.md#start-here).",
        "",
        "## Node Types",
        "",
        "| Node Type | Display Name | Icon | Description |",
        "| --- | --- | --- | --- |",
    ]
    for node in nodes:
        lines.append(
            f"| `{node['name']}` | {escape(node.get('display_name'))} | "
            f"`{escape(node.get('icon'))}` | {escape(node.get('description'))} |"
        )

    lines.extend(["", "## Structural and Containment Edges", ""])
    lines.extend(relationship_table(structural))
    lines.extend(["", "## Access-Control and Impact Edges", ""])
    lines.extend(relationship_table(access))
    lines.extend([
        "",
        "## Regeneration",
        "",
        "```powershell",
        "python Documentation/tools/generate_schema_reference.py",
        "python Documentation/tools/generate_schema_reference.py --check",
        "```",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if SCHEMA.md is stale")
    args = parser.parse_args()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    rendered = render(schema)
    if args.check:
        current = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else ""
        if current != rendered:
            print(f"{OUTPUT_PATH} is stale")
            return 1
        print(f"{OUTPUT_PATH} is current")
        return 0
    OUTPUT_PATH.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
