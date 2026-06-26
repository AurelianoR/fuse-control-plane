# Fuse — third-party token governance console

Fuse gives you one place to **see, monitor and lock down every third-party token**
connected to your SaaS data — and for the connections that matter most, it makes
a stolen token useless to an attacker.

When a SaaS vendor is breached, attackers replay the long-lived tokens it holds
straight against your platform, skipping MFA and firewalls (Salesloft–Drift,
2025). Fuse closes that gap in three tiers, and the lower two need nothing from
any vendor:

1. **Visibility** — inventory every vendor app, grant and token: scope, age,
   last used, by whom, consent chain, publisher.
2. **Policy** — shorten token lifetimes, minimize scope, or revoke — per
   connection or per company. Cuts the breach window from months to minutes.
3. **Cryptographic binding (DPoP)** — for high-value connections, tie the token
   to a private key the vendor never lets leave its machine. A thief who steals
   the token but not the key can't use it.

Everything is **real crypto**: Fuse-issued tokens are ES256 JWTs; vendors
authenticate with **private_key_jwt** (RFC 7523) and sign **DPoP** proofs
(RFC 9449) with keys that stay at the vendor. The GitHub connector authenticates
as a real **GitHub App**; the Azure connector uses a real **app registration**
against Microsoft Graph.

---

## The console

Served by Fuse on **:8000** (single self-contained SPA, same-origin API). Pick a
company from the switcher at the bottom of the sidebar — the **Dashboard** and
**Connectors** scope to it; "All companies" shows each one side by side.

- **Dashboard** — a KPI overview (Azure/Entra apps, GitHub apps, bound tokens,
  high-risk, compliance findings, total connections, connected sources, audit
  events). Every stat is clickable and routes into its detail view. On "All
  companies" it also renders a per-company breakdown.
- **Connectors** — organize sources under **companies**. Add a company, then add
  connectors under it (Demo Company, Demo Vendor, GitHub App, Azure/Entra). Each
  prompts for its own config; secrets are entered at runtime, never in code.
  **⚡ Quick-connect demo** wires the bundled company + vendor in one click.
- **Token Monitor** — the grant inventory: every OAuth grant, app install, PAT
  and OAuth authorization across companies. Click any row for a **full-screen
  detail**: risk signals + explanations, identity, activity (last used / by
  whom), consent chain, publisher verification, a **compliance checklist**,
  permissions, event history, and revoke.
- **Gateway** — the inline DPoP demo. Pick a key-holding connection and run it
  through Fuse: the legit vendor call (forwarded) and three attacker runs
  (stolen token, forged proof, replayed proof) that all stop at the gateway. A
  live circuit shows the request flowing Vendor → Fuse → Company with each
  binding check lighting up. A binding-posture donut sits on top.
- **Policy** — govern the sender-bound (gateway) tokens **per company**: set
  each token's DPoP binding and expiry, or apply a group policy to a whole
  company at once.
- **Compliance** — negative status only: the concrete risk findings that need
  action (write/admin scope, unverified publisher, dormant, user-consented,
  unbound bearer), ranked by severity, each linking to the affected connections.
- **Audit Log** — every connector sync, policy change, revocation, gateway
  allow/block and breach attempt, newest first — with **Export report**.
- **Product Presentation** — a static marketing/overview page at
  `/static/presentation.html`.

## Revoke — or redirect to the provider

Revoke is not cosmetic. For a governable connection Fuse revokes the outstanding
token and blocks further calls. For a **real Azure app** it calls Microsoft
Graph to delete the `oauth2PermissionGrants` and disable the service principal;
for a **GitHub** app it deletes the installation. When Fuse **can't** cut a
connection from its side, the detail screen instead links straight to the
**provider's own revoke screen** (Entra admin, GitHub installations, Salesforce).

## Inline DPoP gateway

Besides the out-of-band path (vendor calls the platform directly, platform
verifies the proof), this build includes the **inline gateway**: a vendor routes
its DPoP-bound request *through Fuse*, which verifies the proof itself and
forwards only verified requests to the company with a signed assertion the
company trusts. Fuse's `GET /gateway/contacts` runs the four DPoP checks
(real token · key thumbprint match · request match · freshness/replay) and
denies a stolen token or forged proof at the gateway (401) before anything
reaches the company.

```bash
curl -X POST http://localhost:8020/gateway-call/PipelineCRM \
  -H 'content-type: application/json' \
  -d '{"gateway_url":"http://localhost:8000/gateway/contacts"}'
```

## Architecture

| Folder         | Role                                                              | Port |
|----------------|-------------------------------------------------------------------|------|
| `fuse/`        | Console + token authority + adapter/grant/policy/compliance API   | 8000 |
| `company_api/` | Mock data platform; enforces token + DPoP + scope + revocation    | 8010 |
| `vendor/`      | Real vendors; hold their own keys; sign their own DPoP proofs     | 8020 |
| `connectors/`  | Connector framework: demo_company, demo_vendor, github, azure     | —    |
| `common/`      | Crypto: EC keys, DPoP, JWK thumbprints, private_key_jwt, GH app JWT| —    |
| `web/`         | Grant-inventory store (SQLAlchemy/SQLite) + risk logic + demo seed | —    |
| `collector/`   | Real MS Graph / GitHub collection + revoke (source of risk logic)  | —    |

The grant inventory is served **natively** by Fuse (`/api/grants`,
`/api/grant/{id}`) from the seeded `web/` store, so the Token Monitor is one app
on one origin — no second service. Connecting a source is always **manual**;
nothing auto-registers.

### Key API endpoints (all under `:8000`, JSON)

| Method · Path | Used by |
|---|---|
| `GET /api/sessions` | Dashboard connections (live + seeded), with company |
| `GET /api/grants` | Token Monitor inventory, grouped by company; filter by `source`/`platform`/`risk`/`type`/`search` |
| `GET /api/grant/{id}` | Full detail incl. compliance checklist, risk signals, events, provider-revoke links |
| `GET /api/policy/overview` · `POST /api/policy/bulk` · `POST /api/apps/{id}/policy` | Policy view (per company / per token) |
| `GET /api/compliance/findings` | Compliance view + alert badge |
| `POST /api/tokens/revoke` | Revoke a connection |
| `GET/POST /api/companies` · `GET/POST /api/connectors` | Companies + connectors |
| `GET /gateway/contacts` + `POST /api/simulate/gateway*` | Inline DPoP gateway demo |

## Run locally

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./run.sh
```

`run.sh` starts all three services and seeds the demo grant inventory. Open
**http://localhost:8000** and:

1. **Connectors → ⚡ Quick-connect demo** — wires the company (:8010) + vendor
   (:8020) under an "Acme Corp (Demo)" company; the Dashboard and Token Monitor
   fill immediately.
2. **Gateway** — toggle **Require binding** on a connection, then **Run legit
   request** (ALLOWED) and the attacker runs (BLOCKED). A stolen token without
   the key fails.
3. **Token Monitor** — click any token for the full detail + compliance
   checklist. **Policy** — set per-token DPoP/expiry or a company-wide group
   policy. **Compliance** — review the non-compliant findings.

> In-memory & single-worker by design: a restart resets state and regenerates
> Fuse's signing key. Companies, policies and connectors are session-scoped.

## Connect a real GitHub App

Create a GitHub App (Settings → Developer settings → GitHub Apps) with read
permissions (Metadata: read; for org app inventory, Organization
administration: read), generate a **private key** (.pem), and install it. In
**Connectors → Add a Source → GitHub**, enter the App ID, the .pem contents, and
optionally the installation ID / org login. Fuse signs an app JWT, mints a real
installation token, and surfaces the org's installed apps.

## Connect a real Azure / Entra tenant

Register an app, add **application** Graph permissions (e.g.
`Application.Read.All`, `Directory.Read.All`), grant **admin consent**, and
create a **client secret**. In **Connectors → Add a Source → Azure**, enter the
Tenant ID, Client ID and Client secret. Fuse gets a client-credentials Graph
token and lists the tenant's third-party enterprise apps and the scopes they
were granted (revoke needs `*.ReadWrite.All` + consent).

## Configuration (env vars)

`run.sh` sets sensible defaults; override as needed:

| Var | Default | Purpose |
|---|---|---|
| `FUSE_URL` | `http://localhost:8000` | Fuse base / private_key_jwt audience (must match on Fuse + Vendor) |
| `COMPANY_API_URL` | `http://localhost:8010` | Company data API |
| `VENDOR_URL` | `http://localhost:8020` | Vendor service |
| `DATABASE_URL` | `sqlite:///./fuse_monitor.db` | Grant-inventory store |
| `SECRET_ENCRYPTION_KEY` | (derived in `run.sh`) | Fernet key for the grant store; set your own in prod |

## What is real vs simplified

**Real:** all crypto; private_key_jwt client auth; DPoP and the four checks;
scope / lifetime / revocation enforcement; the GitHub App and Azure
client-credentials flows; vendor private keys staying at the vendor; the grant
inventory's risk-signal and activity logic (ported from the collector).
**Simplified:** the demo company's discovered list and the seeded "Acme Corp"
collector tenants are illustrative; Fuse's signing key is in memory (use an HSM /
Key Vault in prod); one vendor service stands in for several; Fuse plays the
attacker in the gateway demo.

## Limits

Single instance, single worker, in-memory + local SQLite state — do not scale
out. A restart resets state and regenerates Fuse's signing key. No auth on the
console; add an auth proxy before exposing it. Binding defends against token
theft, not host compromise, and only protects connections whose vendor has
adopted the key step — the long tail falls back to visibility + policy.
