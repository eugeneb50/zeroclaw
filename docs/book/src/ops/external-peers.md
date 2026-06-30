# External A2A Peers

External A2A peers are agents outside your ZeroClaw deployment that can submit
A2A tasks to agents in a peer group. Unlike local agents (listed in `agents`),
external peers authenticate with a bearer credential rather than being members
of the deployment's identity domain.

## When to use external_peers vs. adding to the agents list

| Scenario | Use |
|---|---|
| CI/CD system (Jenkins, GitHub Actions) submits tasks to an agent | `a2a_external_peers` |
| A team-mate's ZeroClaw instance sends cross-org A2A requests | `a2a_external_peers` |
| A local agent in the same config file should be reachable | `agents` |
| A human user interacts via a chat channel (Telegram, Slack) | `external_peers` (channel usernames) |

## Configuration

External peer credentials are declared inline in the peer group, under
`[peer_groups.<name>.a2a_external_peers.<peer_id>]`:

```toml
[peer_groups.ops-team]
agents = ["ops-bot-alpha", "ops-bot-beta"]

# External A2A agents that can act AS IF they are members of this
# peer group. The table key is the peer ID (appears in audit logs).
[peer_groups.ops-team.a2a_external_peers.infra-jenkins]
credential = "sk-jenkins-secret"
# Optional: restrict which agent aliases this peer may target.
# If absent, the peer inherits the parent group's `agents` list.
allowed_aliases_override = ["ops-bot-alpha"]
```

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `credential` | string | yes | Bearer token the external agent presents |
| `allowed_aliases_override` | string list | no | Restrict target aliases; inherits `agents` when absent |

### Collision behaviour

When a peer group has both `agents` and `a2a_external_peers` entries for the
same alias name, the sets are **unioned** at verify time — an external peer
with no `allowed_aliases_override` inherits the full `agents` list, and the
`[a2a.peers]` top-level section is checked independently. This is by design:
external peers are scoped to their peer group, never added to the global
`[a2a.peers]` table.

## Security

- Credentials are stored in plaintext in the config file. Protect your
  `config.toml` with filesystem permissions (0600).
- At verify time, both the presented token and the stored credential are
  SHA-256 hashed and compared with a constant-time equality function.
- TLS termination at the gateway is required for production use.
- For credential rotation: update the `credential` value in config and
  SIGHUP-reload the gateway — no restart needed.

## Troubleshooting

**"Unauthorized" for an external peer**
1. Verify the peer group name and peer ID match between `[peer_groups.<name>.a2a_external_peers.<peer_id>]` and the `peer_group` claim in the request.
2. Confirm the bearer token in the `Authorization` header matches the `credential` value exactly (whitespace is significant).
3. Check the gateway audit log for the credential hash comparison outcome.

**External peer sees "403 Forbidden" on a specific agent alias**
1. Check whether `allowed_aliases_override` is set. If present, it replaces — does not extend — the parent group's `agents` list.
2. The target alias must be in the resolved alias set.
