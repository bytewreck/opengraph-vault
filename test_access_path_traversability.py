import unittest

import vault_collector as vc


def graph_node(node_id, kind):
    return vc.GraphNode(node_id, [kind], {"name": node_id})


class KvKindTests(unittest.TestCase):
    def test_files_and_directories_have_distinct_kind_stacks(self):
        self.assertEqual(vc.get_kv_kinds("file"), ["Vault_KvFile"])
        self.assertEqual(vc.get_kv_kinds("directory"), ["Vault_KvDirectory"])


class OktaGroupAliasCorrelationTests(unittest.TestCase):
    def test_group_maps_to_same_mount_alias_case_insensitively(self):
        collector = vc.VaultCollector(None, "https://vault.test")
        collector._auth_methods["okta-accessor"] = {
            "type": "okta",
            "node_id": "okta-mount",
        }
        collector._auth_methods["other-accessor"] = {
            "type": "okta",
            "node_id": "other-okta-mount",
        }
        collector._auth_okta_groups["okta-accessor"] = {
            "Vault-Admins": {
                "node_id": "okta-group-vault-admins",
                "name": "Vault-Admins",
                "accessor": "okta-accessor",
            }
        }
        collector._group_aliases.update({
            "matching-alias": {
                "id": "matching-alias",
                "name": "vault-admins",
                "mount_accessor": "okta-accessor",
                "canonical_id": "vault-admin-group",
            },
            "foreign-alias": {
                "id": "foreign-alias",
                "name": "Vault-Admins",
                "mount_accessor": "other-accessor",
                "canonical_id": "foreign-admin-group",
            },
        })
        collector._group_alias_nodes.update({
            "matching-alias": "group-alias-matching",
            "foreign-alias": "group-alias-foreign",
        })
        collector._group_by_id.update({
            "vault-admin-group": {"id": "vault-admin-group"},
            "foreign-admin-group": {"id": "foreign-admin-group"},
        })

        collector._compute_alias_edges()

        okta_group_edges = [
            edge for edge in collector.edges
            if edge.kind == "Vault_MapsTo"
            and edge.source == "okta-group-vault-admins"
        ]
        self.assertEqual(len(okta_group_edges), 1)
        self.assertEqual(okta_group_edges[0].target, "group-alias-matching")


class LdapCheckoutTraversalTests(unittest.TestCase):
    def test_checkout_targets_only_observed_available_accounts(self):
        collector = vc.VaultCollector(None, "https://vault.test")
        engine = {
            "accessor": "ldap-accessor",
            "path": "ldap/",
            "node_id": "ldap-mount",
        }
        library = {
            "node_id": "library-team",
            "name": "team",
            "parent_node_id": "ldap-mount",
            "properties": {},
        }
        collector._ldap_library_sets["ldap-accessor"] = {"team": library}
        collector._ldap_service_accounts["ldap-accessor"] = {
            "team:available": {
                "node_id": "account-available",
                "name": "available",
                "parent_node_id": "library-team",
                "status_known": True,
                "available": True,
                "properties": {},
            },
            "team:busy": {
                "node_id": "account-busy",
                "name": "busy",
                "parent_node_id": "library-team",
                "status_known": True,
                "available": False,
                "properties": {},
            },
            "team:unknown": {
                "node_id": "account-unknown",
                "name": "unknown",
                "parent_node_id": "library-team",
                "status_known": False,
                "available": None,
                "properties": {},
            },
        }
        collector.nodes.extend([
            graph_node("library-team", "Vault_LdapLibrarySet"),
            graph_node("account-available", "Vault_LdapServiceAccount"),
            graph_node("account-busy", "Vault_LdapServiceAccount"),
            graph_node("account-unknown", "Vault_LdapServiceAccount"),
        ])

        collector._emit_ldap_checkout_targets(
            "policy",
            engine,
            "team",
            ["update"],
            "ldap/library/team/check-out",
            "ldap/library/team/check-out",
        )

        checkout_edges = [
            edge
            for edge in collector.edges
            if edge.kind == "Vault_LdapCheckoutServiceAccount"
        ]
        potential_targets = {
            edge.target
            for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
        }
        self.assertEqual([edge.target for edge in checkout_edges], ["account-available"])
        self.assertEqual(potential_targets, {"account-busy", "account-unknown"})
        self.assertTrue(all(edge.target != "library-team" for edge in collector.edges))
        self.assertEqual(
            checkout_edges[0].properties["availability_states"],
            ["Available"],
        )


class ApproleSecretIdTraversalTests(unittest.TestCase):
    @staticmethod
    def collector(parsed_paths):
        collector = vc.VaultCollector(None, "https://vault.test")
        collector._auth_methods["approle-accessor"] = {
            "type": "approle",
            "path": "auth/approle/",
            "node_id": "approle-mount",
        }
        collector._auth_approle_roles["approle-accessor"] = {
            "web": {
                "node_id": "approle-role-web",
                "name": "web",
                "role_id": "collector-observed-role-id",
                "bind_secret_id": True,
            }
        }
        collector._policies["test"] = {
            "node_id": "policy",
            "type": "acl",
            "parsed_paths": parsed_paths,
        }
        collector.nodes.extend([
            graph_node("approle-mount", "Vault_AuthMethodApprole"),
            graph_node("approle-role-web", "Vault_AuthApproleRole"),
        ])
        return collector

    def test_generation_is_potential_without_role_id_access(self):
        secret_id_path = "auth/approle/role/web/secret-id"
        collector = self.collector([
            {"path": secret_id_path, "capabilities": ["update"]},
        ])

        collector._check_auth_approle_access(
            "policy", secret_id_path, ["update"], secret_id_path
        )

        self.assertFalse(any(
            edge.kind == "Vault_AuthApproleGenerateSecretId"
            for edge in collector.edges
        ))
        potential = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
        )
        self.assertEqual(potential.target, "approle-role-web")
        self.assertFalse(potential.properties["role_id_obtainable"])

    def test_generation_traverses_when_policy_can_read_role_id(self):
        secret_id_path = "auth/approle/role/web/secret-id"
        role_id_path = "auth/approle/role/web/role-id"
        collector = self.collector([
            {"path": secret_id_path, "capabilities": ["update"]},
            {"path": role_id_path, "capabilities": ["read"]},
        ])

        collector._check_auth_approle_access(
            "policy", secret_id_path, ["update"], secret_id_path
        )

        edge = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_AuthApproleGenerateSecretId"
        )
        self.assertEqual(edge.target, "approle-role-web")
        self.assertTrue(edge.properties["role_id_obtainable"])
        self.assertEqual(edge.properties["role_id_sources"], ["Read Role ID"])

    def test_exact_role_id_deny_overrides_broad_grant(self):
        role_id_path = "auth/approle/role/web/role-id"
        collector = self.collector([
            {"path": "auth/approle/*", "capabilities": ["read", "update"]},
            {"path": role_id_path, "capabilities": ["deny"]},
        ])

        collector._check_auth_approle_access(
            "policy",
            "auth/approle/*",
            ["read", "update"],
            "auth/approle/*",
        )

        self.assertFalse(any(
            edge.kind == "Vault_AuthApproleGenerateSecretId"
            for edge in collector.edges
        ))
        potential = [
            edge
            for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
            and edge.target == "approle-role-web"
        ]
        self.assertTrue(potential)
        self.assertTrue(all(
            edge.properties["role_id_obtainable"] is False
            for edge in potential
        ))


class IdentityTokenTraversalTests(unittest.TestCase):
    @staticmethod
    def collector(allowed_client_ids=None, include_key=True):
        collector = vc.VaultCollector(None, "https://vault.test")
        role = {
            "node_id": "identity-role-web",
            "name": "web",
            "key": "web-key",
            "client_id": "web-client",
        }
        collector._oidc_token_roles["web"] = role
        if include_key:
            collector._oidc_keys["web-key"] = {
                "allowed_client_ids": allowed_client_ids or [],
            }
        collector.nodes.append(graph_node("identity-role-web", "Vault_OidcTokenRole"))
        return collector

    @staticmethod
    def emit(collector):
        collector._emit_identity_token_generation_edge(
            "policy",
            "identity-role-web",
            ["read"],
            "identity/oidc/token/web",
            "identity/oidc/token/web",
            "exact",
        )

    def test_unknown_signing_key_is_potential(self):
        collector = self.collector(include_key=False)
        self.emit(collector)

        self.assertFalse(any(
            edge.kind == "Vault_GenerateIdentityToken"
            for edge in collector.edges
        ))
        potential = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
        )
        self.assertEqual(potential.target, "identity-role-web")
        self.assertEqual(potential.properties["key_eligibility"], ["Unknown"])
        self.assertEqual(
            potential.properties["requirements"],
            ["Signing Key Allows Role Client ID"],
        )

    def test_allowed_signing_key_is_traversable(self):
        collector = self.collector(["web-client"])
        self.emit(collector)

        edge = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_GenerateIdentityToken"
        )
        self.assertEqual(edge.target, "identity-role-web")
        self.assertEqual(edge.properties["key_eligibility"], ["Allowed"])

    def test_empty_signing_key_allowlist_emits_no_attack_edge(self):
        collector = self.collector([])
        self.emit(collector)

        self.assertFalse(any(
            edge.kind in {"Vault_GenerateIdentityToken", "Vault_PotentialAccess"}
            for edge in collector.edges
        ))


class GcpKmsTraversalTests(unittest.TestCase):
    @staticmethod
    def collector(purpose, synthetic=False):
        collector = vc.VaultCollector(None, "https://vault.test")
        engine = {
            "accessor": "gcpkms-accessor",
            "path": "gcpkms/",
            "node_id": "gcpkms-mount",
        }
        key = {
            "node_id": "gcpkms-key-app",
            "name": "app",
            "purpose": purpose,
            "synthetic": synthetic,
        }
        collector._gcpkms_keys["gcpkms-accessor"] = {"app": key}
        collector.nodes.append(graph_node("gcpkms-key-app", "Vault_GcpKmsKey"))
        return collector, engine

    @staticmethod
    def emit(collector, engine, edge_kind):
        operation = "sign" if edge_kind == "Vault_GcpKmsSign" else "decrypt"
        collector._emit_gcpkms_key_targets(
            "policy",
            engine,
            "app",
            edge_kind,
            ["create", "read", "update", "delete", "list", "sudo"],
            f"gcpkms/{operation}/app",
            f"gcpkms/{operation}/app",
        )

    def test_compatible_decrypt_purpose_is_traversable(self):
        collector, engine = self.collector("asymmetric_decrypt")
        self.emit(collector, engine, "Vault_GcpKmsDecrypt")

        edge = next(edge for edge in collector.edges if edge.kind == "Vault_GcpKmsDecrypt")
        self.assertEqual(edge.properties["compatibility_status"], "Compatible")

    def test_unknown_decrypt_purpose_is_potential(self):
        collector, engine = self.collector("unknown")
        self.emit(collector, engine, "Vault_GcpKmsDecrypt")

        self.assertFalse(any(edge.kind == "Vault_GcpKmsDecrypt" for edge in collector.edges))
        potential = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
        )
        self.assertEqual(potential.properties["compatibility_status"], "Unknown")
        self.assertEqual(
            potential.properties["potential_outcomes"],
            ["Decrypt with GCP KMS Key"],
        )
        self.assertEqual(potential.properties["capabilities"], ["create", "update"])

    def test_incompatible_decrypt_purpose_emits_no_edge(self):
        collector, engine = self.collector("asymmetric_sign")
        self.emit(collector, engine, "Vault_GcpKmsDecrypt")

        self.assertFalse(collector.edges)

    def test_unknown_sign_purpose_is_potential(self):
        collector, engine = self.collector("unknown")
        self.emit(collector, engine, "Vault_GcpKmsSign")

        self.assertFalse(any(edge.kind == "Vault_GcpKmsSign" for edge in collector.edges))
        potential = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
        )
        self.assertEqual(
            potential.properties["potential_outcomes"],
            ["Sign with GCP KMS Key"],
        )
        self.assertEqual(potential.properties["capabilities"], ["create", "update"])


class AwsCredentialPrerequisiteTests(unittest.TestCase):
    @staticmethod
    def collector(credential_types, mfa_serial=None):
        collector = vc.VaultCollector(None, "https://vault.test")
        engine = {
            "accessor": "aws-accessor",
            "path": "aws/",
            "node_id": "aws-mount",
        }
        properties = {"Credential Types": credential_types}
        if mfa_serial:
            properties["MFA Serial Number"] = mfa_serial
        collector._aws_roles["aws-accessor"] = {
            "web": {
                "node_id": "aws-role-web",
                "name": "web",
                "collection_complete": True,
                "synthetic": False,
                "properties": properties,
            }
        }
        collector.nodes.append(graph_node("aws-role-web", "Vault_AwsRole"))
        return collector, engine

    @staticmethod
    def emit(collector, engine):
        collector._emit_aws_role_targets(
            "policy",
            engine,
            "web",
            "Vault_AwsGenerateCredentials",
            ["create", "read", "update"],
            "aws/creds/web",
            "aws/creds/web",
        )

    def test_mfa_only_session_token_is_potential(self):
        collector, engine = self.collector(
            ["session_token"],
            "arn:aws:iam::123456789012:mfa/operator",
        )
        self.emit(collector, engine)

        self.assertFalse(any(edge.kind == "Vault_GenerateCredentials" for edge in collector.edges))
        potential = next(edge for edge in collector.edges if edge.kind == "Vault_PotentialAccess")
        self.assertEqual(potential.properties["capabilities"], ["read"])
        self.assertEqual(potential.properties["prerequisite_status"], "Unknown")
        self.assertEqual(
            potential.properties["requirements"],
            ["Session Token Credentials Require An MFA Code"],
        )

    def test_non_mfa_mode_remains_traversable(self):
        collector, engine = self.collector(["assumed_role"])
        self.emit(collector, engine)

        edge = next(edge for edge in collector.edges if edge.kind == "Vault_GenerateCredentials")
        self.assertEqual(edge.properties["prerequisite_status"], "Viable")
        self.assertEqual(edge.properties["modes"], ["Assumed Role Credentials"])

    def test_mixed_role_splits_viable_and_mfa_dependent_modes(self):
        collector, engine = self.collector(
            ["assumed_role", "session_token"],
            "arn:aws:iam::123456789012:mfa/operator",
        )
        self.emit(collector, engine)

        generated = next(edge for edge in collector.edges if edge.kind == "Vault_GenerateCredentials")
        potential = next(edge for edge in collector.edges if edge.kind == "Vault_PotentialAccess")
        self.assertEqual(generated.properties["modes"], ["Assumed Role Credentials"])
        self.assertEqual(potential.properties["modes"], ["Session Token Credentials"])


class DatabaseCredentialPrerequisiteTests(unittest.TestCase):
    @staticmethod
    def collector(
        *,
        connection_present=True,
        connection_collection_complete=True,
        allowed_roles=None,
        plugin_support=True,
    ):
        collector = vc.VaultCollector(None, "https://vault.test")
        engine = {
            "accessor": "database-accessor",
            "path": "database/",
            "node_id": "database-mount",
        }
        role = {
            "node_id": "database-role-web",
            "name": "web",
            "connection_name": "main",
            "credential_type": "password",
            "collection_complete": True,
            "synthetic": False,
            "properties": {},
        }
        collector._database_roles["database-accessor"] = {"web": role}
        collector._database_connection_collection_complete["database-accessor"] = (
            connection_collection_complete
        )
        if connection_present:
            collector._database_connections["database-accessor"] = {
                "main": {
                    "node_id": "database-connection-main",
                    "name": "main",
                    "allowed_roles": ["web"] if allowed_roles is None else allowed_roles,
                    "collection_complete": connection_collection_complete,
                    "synthetic": False,
                    "plugin_name": "postgresql-database-plugin",
                    "plugin_profile": {
                        "supports_dynamic_roles": plugin_support,
                        "supports_static_roles": plugin_support,
                        "supported_credential_types": ["password"],
                        "capability_source": "test",
                    },
                    "properties": {},
                }
            }
        collector.nodes.append(graph_node("database-role-web", "Vault_DatabaseRole"))
        return collector, engine

    @staticmethod
    def emit_dynamic(collector, engine):
        collector._emit_database_targets(
            "policy",
            engine,
            "role",
            "web",
            "Vault_DatabaseGenerateCredentials",
            ["create", "read", "update"],
            "database/creds/web",
            "database/creds/web",
        )

    def test_proven_connection_emits_traversable_generation(self):
        collector, engine = self.collector()
        self.emit_dynamic(collector, engine)

        edge = next(edge for edge in collector.edges if edge.kind == "Vault_GenerateCredentials")
        self.assertEqual(edge.properties["prerequisite_status"], "Viable")
        self.assertEqual(edge.properties["current_usable_roles"], ["web"])

    def test_uncollected_connection_emits_potential_access(self):
        collector, engine = self.collector(
            connection_present=False,
            connection_collection_complete=False,
        )
        self.emit_dynamic(collector, engine)

        self.assertFalse(any(edge.kind == "Vault_GenerateCredentials" for edge in collector.edges))
        potential = next(edge for edge in collector.edges if edge.kind == "Vault_PotentialAccess")
        self.assertEqual(potential.properties["capabilities"], ["read"])
        self.assertEqual(potential.properties["prerequisite_status"], "Unknown")
        self.assertNotIn("current_usable_roles", potential.properties)

    def test_missing_connection_after_complete_collection_is_blocked(self):
        collector, engine = self.collector(
            connection_present=False,
            connection_collection_complete=True,
        )
        self.emit_dynamic(collector, engine)

        self.assertFalse(collector.edges)

    def test_disallowed_role_is_blocked(self):
        collector, engine = self.collector(allowed_roles=["other-role"])
        self.emit_dynamic(collector, engine)

        self.assertFalse(collector.edges)

    def test_static_credentials_do_not_depend_on_live_connection_viability(self):
        collector, engine = self.collector(
            connection_present=False,
            connection_collection_complete=True,
        )
        collector._database_static_roles["database-accessor"] = {
            "web": collector._database_roles["database-accessor"]["web"],
        }
        collector.nodes[-1] = graph_node("database-role-web", "Vault_DatabaseStaticRole")

        collector._emit_database_targets(
            "policy",
            engine,
            "static_role",
            "web",
            "Vault_DatabaseGetStaticCredentials",
            ["read"],
            "database/static-creds/web",
            "database/static-creds/web",
        )

        self.assertTrue(any(edge.kind == "Vault_ReadStaticCredentials" for edge in collector.edges))


class ScimResourceTraversalTests(unittest.TestCase):
    @staticmethod
    def collector(policy_path, capabilities):
        collector = vc.VaultCollector(None, "https://vault.test")
        collector._entity_by_id.update({
            "principal": {
                "id": "principal",
                "name": "principal",
                "disabled": False,
                "policies": ["scim-policy"],
            },
            "owned-user": {
                "id": "owned-user",
                "name": "owned-user",
                "scim_client_id": "client-id",
            },
            "foreign-user": {
                "id": "foreign-user",
                "name": "foreign-user",
                "scim_client_id": "other-client-id",
            },
        })
        collector._group_by_id.update({
            "owned-group": {
                "id": "owned-group",
                "name": "owned-group",
                "scim_client_id": "client-id",
            },
        })
        collector._scim_clients["provisioner"] = {
            "name": "provisioner",
            "node_id": "scim-client",
            "client_id": "client-id",
            "access_grant_principal": "principal",
        }
        collector._policies["scim-policy"] = {
            "node_id": "scim-policy",
            "type": "acl",
            "parsed_paths": [{
                "path": policy_path,
                "capabilities": capabilities,
            }],
        }
        collector.nodes.extend([
            graph_node(collector._id("entity", "principal"), "Vault_Entity"),
            graph_node(collector._id("entity", "owned-user"), "Vault_Entity"),
            graph_node(collector._id("entity", "foreign-user"), "Vault_Entity"),
            graph_node(collector._id("group", "owned-group"), "Vault_Group"),
            graph_node("scim-client", "Vault_ScimClient"),
        ])
        return collector

    def test_users_glob_targets_only_owned_users(self):
        collector = self.collector(
            "identity/scim/v2/Users/*",
            ["update"],
        )

        collector._compute_entity_scim_access_edges()

        provision_edges = [
            edge for edge in collector.edges
            if edge.kind == "Vault_ScimProvisionResources"
        ]
        self.assertEqual(
            [edge.target for edge in provision_edges],
            [collector._id("entity", "owned-user")],
        )
        self.assertEqual(provision_edges[0].properties["scim_targets"], ["Users"])
        self.assertEqual(provision_edges[0].properties["scopes"], ["pattern"])
        self.assertFalse(any(
            edge.target == collector._id("group", "owned-group")
            for edge in provision_edges
        ))
        self.assertFalse(any(
            edge.target == "scim-client"
            for edge in provision_edges
        ))

    def test_exact_group_patch_targets_only_that_group(self):
        collector = self.collector(
            "identity/scim/v2/Groups/owned-group",
            ["patch"],
        )

        collector._compute_entity_scim_access_edges()

        edge = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_ScimProvisionResources"
        )
        self.assertEqual(edge.target, collector._id("group", "owned-group"))
        self.assertEqual(edge.properties["operations"], ["Manage Group Membership"])
        self.assertEqual(edge.properties["patch_targets"], ["members"])

    def test_collection_create_is_potential(self):
        collector = self.collector(
            "identity/scim/v2/Users",
            ["create"],
        )

        collector._compute_entity_scim_access_edges()

        self.assertFalse(any(
            edge.kind == "Vault_ScimProvisionResources"
            for edge in collector.edges
        ))
        potential = next(
            edge for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
        )
        self.assertEqual(potential.target, "scim-client")
        self.assertEqual(potential.properties["potential_outcomes"], ["Create User"])
        self.assertEqual(
            potential.properties["resolution_status"],
            ["SCIM Collection Creates Unobserved Resources"],
        )

    def test_foreign_resource_is_not_reachable(self):
        collector = self.collector(
            "identity/scim/v2/Users/foreign-user",
            ["update"],
        )

        collector._compute_entity_scim_access_edges()

        self.assertFalse(any(
            edge.kind in {"Vault_ScimProvisionResources", "Vault_PotentialAccess"}
            for edge in collector.edges
        ))


class SamlTrustTraversalTests(unittest.TestCase):
    @staticmethod
    def collector():
        collector = vc.VaultCollector(None, "https://vault.test")
        collector._auth_methods["saml-accessor"] = {
            "type": "saml",
            "accessor": "saml-accessor",
            "path": "auth/saml/",
            "node_id": "saml-mount",
        }
        collector._auth_saml_roles["saml-accessor"] = {
            "admin": {
                "node_id": "saml-role-admin",
                "name": "admin",
                "accessor": "saml-accessor",
            },
            "operator": {
                "node_id": "saml-role-operator",
                "name": "operator",
                "accessor": "saml-accessor",
            },
        }
        collector.nodes.extend([
            graph_node("saml-mount", "Vault_AuthMethodSaml"),
            vc.GraphNode(
                "saml-role-admin",
                ["Vault_AuthSamlRole"],
                {
                    "name": "admin",
                    "Token Bound Cidrs": ["10.0.0.0/8"],
                },
            ),
            graph_node("saml-role-operator", "Vault_AuthSamlRole"),
        ])
        return collector

    @staticmethod
    def emit(collector, path_info):
        collector._dispatch_auth_access(
            "policy",
            "auth/saml/config",
            ["update"],
            policy_path="auth/saml/config",
            path_info=path_info,
        )

    def test_unrestricted_trust_replacement_controls_every_observed_role(self):
        collector = self.collector()
        self.emit(collector, {
            "path": "auth/saml/config",
            "capabilities": ["update"],
        })

        control_edges = [
            edge for edge in collector.edges
            if edge.kind == "Vault_ControlObject"
        ]
        self.assertEqual(
            {edge.target for edge in control_edges},
            {"saml-role-admin", "saml-role-operator"},
        )
        self.assertTrue(all(
            edge.properties["control_methods"]
            == ["Replace SAML Identity Provider Trust"]
            for edge in control_edges
        ))
        self.assertTrue(all(
            edge.properties["impacts"] == ["Forge Accepted SAML Identity"]
            for edge in control_edges
        ))
        admin_edge = next(
            edge for edge in control_edges
            if edge.target == "saml-role-admin"
        )
        self.assertEqual(admin_edge.properties["requirements"], ["Satisfy Token Bound CIDRs"])

    def test_value_constrained_trust_replacement_is_potential(self):
        collector = self.collector()
        self.emit(collector, {
            "path": "auth/saml/config",
            "capabilities": ["update"],
            "allowed_parameters": ["idp_cert"],
            "value_constrained_parameters": ["idp_cert"],
            "allowed_parameter_values": {
                "idp_cert": ["approved-certificate"],
            },
        })

        self.assertFalse(any(
            edge.kind == "Vault_ControlObject"
            for edge in collector.edges
        ))
        potential_edges = [
            edge for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
        ]
        self.assertEqual(
            {edge.target for edge in potential_edges},
            {"saml-role-admin", "saml-role-operator"},
        )
        self.assertTrue(all(
            edge.properties["resolution_status"]
            == ["SAML Identity Provider Trust Is Value-Constrained"]
            for edge in potential_edges
        ))

    def test_routing_only_write_does_not_control_saml_roles(self):
        collector = self.collector()
        self.emit(collector, {
            "path": "auth/saml/config",
            "capabilities": ["update"],
            "allowed_parameters": ["idp_sso_url"],
        })

        self.assertFalse(any(
            edge.kind in {"Vault_ControlObject", "Vault_PotentialAccess"}
            for edge in collector.edges
        ))

    def test_global_wildcard_preserves_parameter_constraints(self):
        collector = self.collector()
        collector._policies["test"] = {
            "node_id": "policy",
            "type": "acl",
            "parsed_paths": [{
                "path": "*",
                "capabilities": ["update"],
                "allowed_parameters": ["idp_sso_url"],
            }],
        }

        collector._compute_access_grant_edges()

        self.assertFalse(any(
            edge.kind in {"Vault_ControlObject", "Vault_PotentialAccess"}
            and edge.target in {"saml-role-admin", "saml-role-operator"}
            for edge in collector.edges
        ))


class CloudFoundryTrustTraversalTests(unittest.TestCase):
    @staticmethod
    def collector():
        collector = vc.VaultCollector(None, "https://vault.test")
        collector._auth_methods["cf-accessor"] = {
            "accessor": "cf-accessor",
            "type": "cf",
            "path": "auth/cf/",
            "node_id": "cf-mount",
        }
        collector._auth_cf_roles["cf-accessor"] = {
            "web": {
                "node_id": "cf-role-web",
                "name": "web",
                "accessor": "cf-accessor",
            },
        }
        collector.nodes.extend([
            graph_node("cf-mount", "Vault_AuthMethodCf"),
            vc.GraphNode(
                "cf-role-web",
                ["Vault_AuthCfRole"],
                {
                    "name": "web",
                    "Bound CIDRs": ["10.0.0.0/8"],
                    "Disable IP Matching": False,
                    "Token Bound CIDRs": ["192.0.2.0/24"],
                },
            ),
        ])
        return collector

    @staticmethod
    def emit(collector, path_info):
        collector._dispatch_auth_access(
            "policy",
            "auth/cf/config",
            path_info["capabilities"],
            policy_path=path_info["path"],
            path_info=path_info,
        )

    def test_unrestricted_identity_ca_replacement_controls_roles(self):
        collector = self.collector()
        self.emit(collector, {
            "path": "auth/cf/config",
            "capabilities": ["update"],
        })

        edge = next(edge for edge in collector.edges if edge.kind == "Vault_ControlObject")
        self.assertEqual(edge.target, "cf-role-web")
        self.assertEqual(
            edge.properties["control_methods"],
            ["Replace Cloud Foundry Instance Identity Trust"],
        )
        self.assertEqual(
            edge.properties["requirements"],
            [
                "Satisfy Role Bound CIDRs",
                "Satisfy Cloud Foundry Instance IP Matching",
                "Satisfy Token Bound CIDRs",
            ],
        )

    def test_value_constrained_identity_ca_replacement_is_potential(self):
        collector = self.collector()
        self.emit(collector, {
            "path": "auth/cf/config",
            "capabilities": ["update"],
            "allowed_parameters": ["identity_ca_certificates"],
            "value_constrained_parameters": ["identity_ca_certificates"],
            "allowed_parameter_values": {
                "identity_ca_certificates": ["approved-ca"],
            },
        })

        self.assertFalse(any(edge.kind == "Vault_ControlObject" for edge in collector.edges))
        edge = next(edge for edge in collector.edges if edge.kind == "Vault_PotentialAccess")
        self.assertEqual(edge.target, "cf-role-web")
        self.assertEqual(
            edge.properties["resolution_status"],
            ["Cloud Foundry Identity Trust Is Value-Constrained"],
        )

    def test_unrelated_config_write_does_not_control_roles(self):
        collector = self.collector()
        self.emit(collector, {
            "path": "auth/cf/config",
            "capabilities": ["update"],
            "allowed_parameters": ["cf_timeout"],
        })

        self.assertFalse(any(
            edge.kind in {"Vault_ControlObject", "Vault_PotentialAccess"}
            for edge in collector.edges
        ))


class TotpAdminEnrollmentTraversalTests(unittest.TestCase):
    @staticmethod
    def collector():
        collector = vc.VaultCollector(None, "https://vault.test")
        collector._entity_by_id.update({
            "entity-alice": {"id": "entity-alice", "name": "alice"},
            "entity-bob": {"id": "entity-bob", "name": "bob"},
        })
        collector.nodes.extend([
            graph_node(collector._id("entity", "entity-alice"), "Vault_Entity"),
            graph_node(collector._id("entity", "entity-bob"), "Vault_Entity"),
        ])
        return collector

    def test_admin_generate_targets_only_parameter_allowed_entity(self):
        collector = self.collector()
        path = "identity/mfa/method/totp/admin-generate"
        collector._check_identity_management(
            "policy",
            path,
            ["update"],
            policy_path=path,
            path_info={
                "path": path,
                "capabilities": ["update"],
                "allowed_parameters": ["entity_id"],
                "value_constrained_parameters": ["entity_id"],
                "allowed_parameter_values": {"entity_id": ["entity-alice"]},
            },
        )

        edges = [edge for edge in collector.edges if edge.kind == "Vault_PotentialAccess"]
        self.assertEqual(
            [edge.target for edge in edges],
            [collector._id("entity", "entity-alice")],
        )
        self.assertEqual(
            edges[0].properties["credential_types"],
            ["TOTP Enrollment Secret"],
        )
        self.assertIn(
            "Possess Primary Authentication Credential",
            edges[0].properties["requirements"],
        )
        self.assertFalse(any(edge.kind == "Vault_ReadCredential" for edge in collector.edges))

    def test_global_wildcard_targets_all_observed_entities_as_potential(self):
        collector = self.collector()
        collector._policies["admin"] = {
            "node_id": "policy",
            "type": "acl",
            "parsed_paths": [{
                "path": "*",
                "capabilities": ["update"],
            }],
        }

        collector._compute_access_grant_edges()

        target_ids = {
            edge.target
            for edge in collector.edges
            if edge.kind == "Vault_PotentialAccess"
            and edge.properties.get("credential_types") == ["TOTP Enrollment Secret"]
        }
        self.assertEqual(target_ids, {
            collector._id("entity", "entity-alice"),
            collector._id("entity", "entity-bob"),
        })


class TransitSigningTargetTests(unittest.TestCase):
    def test_csr_and_message_signing_targets_merge_on_the_key_edge(self):
        collector = vc.VaultCollector(None, "https://vault.test")
        engine = {
            "accessor": "transit-accessor",
            "path": "transit/",
            "node_id": "transit-mount",
        }
        collector._transit_keys["transit-accessor"] = {
            "signing": {
                "node_id": "transit-key-signing",
                "name": "signing",
                "key_type": "ecdsa-p256",
                "synthetic": False,
            },
        }
        collector.nodes.append(graph_node("transit-key-signing", "Vault_TransitKey"))

        collector._check_transit_access(
            "policy",
            engine,
            "transit/keys/signing/csr",
            ["update"],
        )
        collector._check_transit_access(
            "policy",
            engine,
            "transit/sign/signing",
            ["update"],
        )

        edge = next(edge for edge in collector.edges if edge.kind == "Vault_TransitSign")
        self.assertEqual(edge.target, "transit-key-signing")
        self.assertEqual(
            edge.properties["signing_targets"],
            ["Certificate Signing Request", "Message or Digest"],
        )


if __name__ == "__main__":
    unittest.main()
