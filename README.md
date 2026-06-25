# Fuse — token & app visibility console

A working control plane that discovers every third-party **app** holding access
to your data, shows the **tokens** behind them, and for the ones it can govern,
makes a stolen token useless with standards-based sender binding (DPoP).

Everything is real crypto. Fuse-issued tokens are ES256 JWTs. Vendors
authenticate to the token endpoint with **private_key_jwt** (RFC 7523) and sign
**DPoP** proofs (RFC 9449) with keys that never leave the vendor. The GitHub
connector authenticates as a real **GitHub App** (RS256 app JWT → installation
token); the Azure connector uses a real **app registration + client credentials**
against Microsoft Graph.

## The console — five views

- **Cloud Connectors** — connect sources of visibility, manually. Demo Company,
  Demo Vendor, GitHub, Azure. Each prompts for its own config and connects on
  demand. Secrets are entered here at runtime, never stored in code.
- **Apps** — every third-party app discovered across connectors: platform,
  scopes, risk, token kind. Governable apps get policy controls (lifetime,
  scope, binding) plus the breach simulation. Every app — including real
  Azure/GitHub apps — has a **Revoke access** button that actually cuts access.
- **Gateway** — the dedicated demo of the inline DPoP gateway (see below). Pick
  a bound connection and run, all the way through Fuse: the legit vendor call
  (forwarded to the company) and three attacker runs (stolen token, forged
  proof, replayed proof) that all stop at the gateway. A live circuit shows the
  request flowing Vendor → Fuse → Company, with each binding check lighting up
  and the company going dark whenever an attack is blocked before it arrives.
- **Policies** — set policy per app, or apply a rule **by class**: pick a filter
  (platform / token kind / risk) and an action (shorten lifetime, minimize
  scope, require binding, or revoke) and it applies to every match.
- **Tokens** — every token: the bound tokens Fuse issues, and the real bearer
  tokens cloud connectors surface (GitHub installation tokens, Azure Graph
  tokens). Bound = sender-constrained; bearer = stealable.

## Revoke actually cuts access

Revoke is not cosmetic. For a governable app it revokes the outstanding token
and blocks further calls. For a **real Azure app** it calls Microsoft Graph to
delete the app's `oauth2PermissionGrants` and disable its service principal
(needs `Directory.ReadWrite.All` + admin consent; it reports cleanly if the app
is read-only). For a **GitHub** app it deletes the installation. One switch,
real effect — the plan's "kills a connection everywhere."

## Inline DPoP gateway (the rare-fallback shape)

Besides the out-of-band path (vendor calls the platform directly, platform
verifies), this build includes the **inline gateway** from the plan: a separate
vendor app routes its DPoP-bound request *through Fuse*, which verifies the
proof itself and forwards only verified requests to the company with a signed
gateway assertion the company trusts. Run it from a governable app with **Run
via gateway**, or drive the vendor directly:

```
curl -X POST http://localhost:8020/gateway-call/PipelineCRM \
  -H 'content-type: application/json' -d '{"gateway_url":"http://localhost:8000/gateway/contacts"}'
```

Fuse's `GET /gateway/contacts` runs the four DPoP checks and forwards to the
company's `/contacts/via-gateway`; a stolen token or forged proof is denied at
the gateway (401) before anything reaches the company.

## Architecture

| Folder         | Role                                                       | Port | Azure App |
|----------------|------------------------------------------------------------|------|-----------|
| `fuse/`        | Console + token authority (private_key_jwt) + policy       | 8000 | fuse      |
| `company_api/` | Company data; enforces token + DPoP + scope + revocation   | 8010 | company   |
| `vendor/`      | Real vendors; hold their own keys; sign their own proofs   | 8020 | vendor    |
| `connectors/`  | Connector framework: demo_company, demo_vendor, github, azure | — | library |
| `common/`      | Crypto: EC keys, DPoP, JWK thumbprints, private_key_jwt, GH app JWT | — | library |

Connecting is **manual**: nothing auto-registers. Fuse pulls the company's
discovered apps via `/discover` and the vendor's public keys via `/identity`
only when you connect those connectors.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./run.sh
```

Open **http://localhost:8000**, go to **Cloud Connectors**, and click
**Quick-connect demo** (wires the company + vendor on :8010/:8020). Then:

- **Apps** tab → on PipelineCRM or DataDrift, toggle **require binding**, click
  **Run vendor request** (vendor authenticates with private_key_jwt, signs a
  DPoP proof, calls the company directly). Then the attack buttons: forge proof,
  replay bearer, replay proof (all blocked), legacy bypass (breaches). Minimize
  scope to watch the API reject the vendor's own call.
- **Tokens** tab → see the bound tokens Fuse issued.

## Connect real GitHub

Add a **GitHub** connector. You need a **GitHub App**:
1. Create a GitHub App (Settings → Developer settings → GitHub Apps), give it
   read permissions (e.g. Metadata: read; for org app inventory, Organization
   administration: read), generate a **private key** (.pem), and install it.
2. In the dashboard: App ID, the .pem contents, optionally the installation ID
   and org login.

Fuse signs an app JWT, mints a real installation token, and surfaces the org's
installed apps and the token itself (a real bearer token it can't yet bind —
exactly the gap Fuse closes for vendors that adopt binding).

## Connect real Azure / Entra

Add an **Azure** connector. You need an **app registration**:
1. Register an app, add **application** Graph permissions (e.g.
   `Application.Read.All`, `Directory.Read.All`), grant **admin consent**, and
   create a **client secret**.
2. In the dashboard: Tenant ID, Client ID, Client secret.

Fuse gets a client-credentials Graph token and lists the tenant's third-party
enterprise apps and the scopes they were granted.

## Deploy to Azure App Service

Three apps on one B1 plan (Linux, Python 3.12). Startup commands:
`bash startup_fuse.sh`, `bash startup_company.sh`, `bash startup_vendor.sh`.
Set `FUSE_URL`, `COMPANY_API_URL`, `VENDOR_URL` to the public URLs on each app
(`FUSE_URL` must match on Fuse and Vendor — it's the audience for
private_key_jwt), plus `SCM_DO_BUILD_DURING_DEPLOYMENT=true` and Always On.
See `DEPLOY-VSCODE.md`. Connectors are configured in the UI after deploy.

## What is real vs simplified

Real: all crypto; private_key_jwt client auth; DPoP and the four checks; scope,
lifetime, revocation enforcement; the GitHub App and Azure client-credentials
flows; vendor private keys staying at the vendor. Simplified: the demo company's
discovered list is illustrative; Fuse's signing key is in memory (use Key Vault
in prod); one vendor service stands in for several; Fuse plays the attacker.

## Limits

Single instance, single worker, in-memory state — do not scale out. A restart
resets state and regenerates Fuse's signing key. No auth on the dashboard; add
Easy Auth before exposing it.
