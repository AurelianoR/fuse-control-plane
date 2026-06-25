# Fuse

## Core Problem

Third-party SaaS integrations receive long-lived bearer tokens to access Salesforce, M365, Google Workspace, etc. When a vendor is breached, attackers replay those tokens directly against the platform — bypassing MFA and firewalls, because the token is proof that auth already happened. The breach window is as long as the token's lifetime (often months). Recent examples: Salesloft–Drift (2025), Klue/Icarus, Nintendo/TinyPulse.

Okta-class IAM doesn't help here. It secures human login. Machine-to-machine vendor tokens are outside its scope.

---

## Two Approaches

The fundamental axis is **enforcement vs. zero-disruption visibility**.

---

### Approach A — Proxy (Inline Enforcement)

Fuse sits between vendors and the data platform. Vendors send requests to Fuse; Fuse forwards them with the real platform token.

**What it can do:**
- Issue its own short-lived tokens to vendors (minutes, not months) — stolen Fuse-layer token expires fast
- Instant centralized revocation — one kill-switch instead of hunting per-platform
- Request filtering at the proxy layer (block specific API calls regardless of token permissions)
- Full DPoP sender-binding as an optional tier: cryptographically ties a token to the vendor's private key; stolen token is useless without the key

**Hard limits:**
- Fuse becomes a critical path. If Fuse goes down, vendor integrations stop (customer chooses fail-open or fail-closed per connection).
- Request filtering ≠ scope enforcement. The underlying platform token retains whatever permissions were granted at issuance. Fuse can block calls it sees; it cannot retroactively downscope a token it didn't issue.
- DPoP requires vendor participation — a small client library integration. Without it, sender-binding cannot be enforced.
- Deployment requires repointing vendor traffic from the platform URL to Fuse. New vendors: easy (enter the Fuse URL). Existing vendors: a config change on every connection.

**On Azure specifically:**

Fuse registers as a service principal in the customer's Entra tenant (admin consent once, same flow as any enterprise app). Fuse holds the real Graph token. Vendors authenticate to Fuse, not to `graph.microsoft.com`. The load-bearing assumption is that vendors can and will repoint their Graph API calls to Fuse's endpoint — this needs to be validated per-vendor.

---

### Approach B — Collector (Out-of-Band Visibility)

Fuse does not sit inline. It queries the platform's own admin/audit APIs, builds a live inventory of every vendor token grant, and surfaces risk — without touching any traffic path.

**What it can do:**
- Enumerate all OAuth grants across the tenant (delegated + application permissions)
- Flag over-scoped, dormant, or unrecognized grants
- Alert on anomalous activity (unusual API calls, off-hours access)
- Drive out-of-band revocation (admin deletes the grant via the platform's own UI or via Fuse-triggered API call)

**Hard limits:**
- Enforces nothing. No lifetime control, no request filtering, no DPoP.
- Revocation is lagged. On Entra, you cannot invalidate an already-issued access token mid-flight. Disabling a service principal or deleting a grant stops *new* tokens from being issued, but existing tokens remain valid until they expire (~60–90 minutes by default). Containment after a breach detection is therefore lagged by the token TTL unless Continuous Access Evaluation (CAE) applies to that application. This is the sharpest practical difference from the proxy approach.

**On Azure specifically:**

A registered Entra app with read-only Microsoft Graph permissions (all require admin consent):
- `Application.Read.All` — enumerate all service principals, enterprise apps, and resolve `appRoleId` GUIDs to human-readable permission names
- `Directory.Read.All` — enumerate delegated OAuth grants (`oauth2PermissionGrants`) tenant-wide
- `AuditLog.Read.All` — sign-in logs, directory audit logs, `servicePrincipalSignInActivities`

No license gating on grant enumeration. Entra ID P1/P2 required for sign-in log data and `servicePrincipalSignInActivities` to exist.

This is non-destructive, deploys in minutes, and requires no changes to any vendor or integration.

---

## Azure Collector — What Graph Actually Exposes

### Grant enumeration (free tier, no license required)

**Delegated grants** (`GET /v1.0/oauth2PermissionGrants`): 6 fields only. Notable absence: no `createdDateTime`. The grant creation date is only in the directory audit log for the corresponding consent event — unrecoverable for grants that predate collector deployment. The `scope` field is the current live state; historical scope narrowing is only in the audit log.

**Application grants** (`GET /v1.0/servicePrincipals/{id}/appRoleAssignments`): Does include `createdDateTime`. The `appRoleId` field is an opaque GUID that must be resolved against the resource SP's `appRoles[]` collection to get a human-readable permission name (e.g., `Mail.ReadWrite`). This resolution step is mandatory and must be cached per resource SP.

**Service principal inventory** (`GET /v1.0/servicePrincipals`): `appOwnerOrganizationId` identifies third-party (vendor) SPs — if it differs from the customer's tenant ID, the app was registered by an external vendor. `verifiedPublisher` is a Microsoft-verified trust signal. Delta queries are supported on all three endpoints.

### Activity data (Entra ID P1/P2 required)

**`servicePrincipalSignInActivities` (beta)**: Pre-aggregated last-used timestamps per SP, broken down by flow type (app-only client, app-only resource, delegated client, delegated resource). Persists beyond the 30-day sign-in log window — specifically useful for dormancy detection. Returns 403 on free tenants.

**Sign-in logs** (`GET /v1.0/auditLogs/signIns`): Authentication events (token issuances), not API calls. 30-day retention (P1/P2). Tells you when a token was issued and from where; does not tell you what the vendor did with it.

**Directory audit log** (`GET /v1.0/auditLogs/directoryAudits`): Records consent grants, permission changes, and SP additions/removals. The `"Consent to application"` event's `targetResources[].modifiedProperties` is the only place the original consent-time scope is stored.

### Per-call API visibility (requires Azure Monitor, not a Graph API)

`MicrosoftGraphActivityLogs` in a Log Analytics workspace is the only surface that records individual API calls made to Graph (caller SP, `RequestUri`, HTTP method, response code, `Scopes`, source IP). It is not queryable via the Graph API — requires diagnostic settings in Azure Monitor. Not in scope for the initial collector; requires Azure subscription + additional infrastructure.

### What the collector cannot see

- **Token strings**: Never exposed through any admin API.
- **Currently live token count**: No endpoint returns "how many valid tokens exist right now for this SP."
- **Token expiry for already-issued tokens**: The TTL of a live token is not queryable. Default is ~60 minutes.
- **What a vendor did with its token**: Sign-in logs record authentication events only. Per-call visibility requires Graph Activity Logs (Azure Monitor).

### Revocation mechanics on Azure

Deleting a grant (`oauth2PermissionGrant` or `appRoleAssignment`) stops new tokens but does not invalidate already-issued access tokens. Existing tokens live for their remaining TTL (~60 minutes default).

CAE for workload identities exists but applies only to **single-tenant LOB apps registered in the customer's own tenant**. Multi-tenant SaaS vendors (the primary supply-chain threat) are explicitly excluded — their tokens have no early-revocation mechanism. Disabling the SP (`accountEnabled = false`) is the strongest available containment action; it stops new token issuance but leaves live tokens valid until TTL.

`revokeSignInSessions` applies to users only, not service principals.

---

## Current Focus

**Azure first.** Approach B (collector) is implemented in `collector/`. Approach A (proxy) is the next phase.

Open questions for next iteration:
1. **Proxy feasibility**: Are Graph API client libraries (MSAL, Graph SDK) configurable to a custom base URL, or do they hardcode `graph.microsoft.com`? This is the load-bearing assumption for the proxy path.
2. **CAE behavior in practice**: For the multi-tenant vendor case where CAE doesn't apply, what is the actual measured token TTL — consistently 60 minutes, or does it vary?
3. **Graph Activity Logs cost model**: At what tenant size does the Azure Monitor ingestion cost become non-trivial relative to the security value?

---

## Rollout Model (Proxy Path)

1. **Monitoring mode** — Fuse observes without enforcing. Visibility only, zero disruption.
2. **Enforce per vendor** — Short lifetimes and request filtering, one connection at a time.
3. **Mandate DPoP for priority vendors** — As a condition of continued access for high-risk integrations.

Even without DPoP, the proxy path cuts the breach window from months to minutes (short token lifetimes) and limits blast radius per-connection (request filtering).
