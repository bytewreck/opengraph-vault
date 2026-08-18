# Cypher Query Examples

BloodHound uses Cypher-like graph queries. Property names and support for some functions can vary by BloodHound version.

## Find a Node Kind

```cypher
MATCH (n:Vault_Policy)
RETURN n
```

## Find Nodes with a Kind Prefix

Labels are returned by `labels(n)`. `type()` applies to relationships, not nodes.

```cypher
MATCH (n)
WHERE any(label IN labels(n) WHERE label STARTS WITH 'Vault_Oidc')
RETURN n
```

## Find a Specific Relationship

```cypher
MATCH p = (:Vault_Policy)-[:Vault_KvReadSecret]->(:Vault_KvFile)
RETURN p
```

## Find Relationship Types by Prefix

Cypher does not support `[:Vault_Pki*]` syntax. Filter `type(r)` instead:

```cypher
MATCH p = (source)-[r]->(target)
WHERE type(r) STARTS WITH 'Vault_Pki'
RETURN p
```

## Exclude a Source Name

```cypher
MATCH p = (source)-[r]->(target)
WHERE type(r) STARTS WITH 'Vault_Pki'
  AND source.name <> 'AUTH-ADMIN'
RETURN p
```

## Match One of Several Sources

```cypher
MATCH p = (source)-[*1..]->(target)
WHERE source.name IN ['ALICE', 'BOB', 'CI-RUNNER']
RETURN p
```

You can also use label alternatives in a predicate:

```cypher
MATCH p = (source)-[*1..]->(target)
WHERE source:Vault_Entity OR source:Vault_AuthUser
RETURN p
```

## Shortest Path

```cypher
MATCH (source {name: 'ALICE'}), (target:Vault_KvFile {name: 'PROD/DB'})
MATCH p = shortestPath((source)-[*1..]->(target))
RETURN p
```

Raw Cypher `shortestPath` follows the relationship pattern you provide; it does not automatically consult the OpenGraph schema's traversability flag. BloodHound pathfinding features may apply schema traversal rules separately.

## Shortest Path Using Selected Offensive Edges

```cypher
MATCH (source {name: 'ALICE'}), (target:Vault_KvFile)
MATCH p = shortestPath((source)-[
  :Vault_MapsTo|
   Vault_MemberOf|
   Vault_LinksPolicy|
   Vault_ControlObject|
   Vault_ObtainPolicy|
   Vault_KvReadSecret
*1..]->(target))
RETURN p
```

Some BloodHound Cypher versions do not accept relationship alternation in every variable-length form. The portable alternative is to match broadly and filter:

```cypher
MATCH p = (source {name: 'ALICE'})-[*1..8]->(target:Vault_KvFile)
WHERE all(r IN relationships(p) WHERE type(r) IN [
  'Vault_MapsTo',
  'Vault_MemberOf',
  'Vault_LinksPolicy',
  'Vault_ControlObject',
  'Vault_ObtainPolicy',
  'Vault_KvReadSecret'
])
RETURN p
ORDER BY length(p)
LIMIT 1
```

## Find Policies That Read Secrets

```cypher
MATCH p = (policy:Vault_Policy)-[:Vault_KvReadSecret]->(secret:Vault_KvFile)
RETURN policy.name, secret.name, p
```

## Find Credential Generation

```cypher
MATCH p = (policy:Vault_Policy)-[:Vault_GenerateCredentials]->(role)
RETURN policy.name, labels(role), role.name, p
```

## Find Proven Object Takeover

```cypher
MATCH p = (source)-[r:Vault_ControlObject]->(target)
RETURN source.name,
       target.name,
       r.`Control Methods`,
       r.Impacts,
       p
```

## Find Potential Access

```cypher
MATCH p = (source)-[r:Vault_PotentialAccess]->(target)
RETURN source.name,
       target.name,
       r.`Potential Outcomes`,
       r.`Resolution Status`,
       r.Requirements,
       p
```

## Find Synthetic Objects

```cypher
MATCH (n)
WHERE n.Synthetic = true
RETURN n.name, labels(n), n.Path
```

## Find Template-Derived Access

```cypher
MATCH p = (source)-[r]->(target)
WHERE r.Templated = true
RETURN source.name,
       type(r),
       target.name,
       r.`Matched Policy Paths`,
       r.`Matched Paths`,
       p
```

## Find Traversal into a Policy

```cypher
MATCH p = (source)-[:Vault_ControlObject|Vault_ObtainPolicy*1..2]->(policy:Vault_Policy)
RETURN p
```

## Find Generic Management by Subsystem

```cypher
MATCH p = (policy:Vault_Policy)-[r:Vault_ManageObject]->(target)
WHERE 'Transit' IN r.`Engine Types`
RETURN policy.name, target.name, r.Operations, p
```

Generic edge families should normally be filtered using their contextual properties rather than assuming the relationship name identifies a single backend operation.
