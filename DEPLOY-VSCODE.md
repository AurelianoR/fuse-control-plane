# Deploy to Azure App Service from VS Code

Goal: one App Service **Plan** hosting **three App Services** to save quota.
One app runs Fuse (the dashboard and control plane), one runs the Company Data
API, and one runs the Vendor service (which holds its own signing key and never
hands it to Fuse). They find each other over their public `azurewebsites.net`
URLs, so nothing in the code changes between machines.

You deploy the **same project folder** to all three apps. The only difference
between them is the startup command and a few app settings.

## Before you start

- Install the **Azure App Service** extension in VS Code (part of the "Azure
  Tools" pack). Sign in to your Azure account in the Azure panel.
- Unzip and open the `fuse-demo` folder in VS Code as the workspace root.
- Pick a region and three names you will remember, for example
  `fuse-demo-control`, `fuse-demo-data`, and `fuse-demo-vendor`. Names must be
  globally unique, so add something of your own if they are taken.

## 1. Create the plan and the three apps

Use the **Advanced** create flow so you can pick the runtime, tier, and (for the
later apps) the shared plan: open the command palette and run
**Azure App Service: Create Web App… (Advanced)**.

1. **First app (Fuse):**
   - Runtime **Python 3.12**, OS **Linux**.
   - App Service Plan: **create a new one**, **B1 (Basic)** or higher. Avoid F1
     Free: it has no Always On and tight memory, and this demo wants the process
     to stay warm so in-memory state and the live feed survive.
   - Note the plan it created.

2. **Second app (Company API):** same runtime, same resource group; at the plan
   step **choose the existing plan** from step 1.

3. **Third app (Vendor):** same runtime, same resource group; **existing plan**
   again. All three share one plan — that is the quota-saving setup.

After this you have three URLs:
- Fuse: `https://<fuse-name>.azurewebsites.net`
- Company: `https://<company-name>.azurewebsites.net`
- Vendor: `https://<vendor-name>.azurewebsites.net`

Write all three down. Each app needs the others' URLs.

## 2. Configure the Fuse app

Open the Fuse app (extension → Open in Portal).

**Configuration → General settings → Startup Command:**

```
bash startup_fuse.sh
```

**Configuration → Application settings**, add:

| Name                             | Value                                        |
|----------------------------------|----------------------------------------------|
| `COMPANY_API_URL`                | `https://<company-name>.azurewebsites.net`   |
| `VENDOR_URL`                     | `https://<vendor-name>.azurewebsites.net`    |
| `FUSE_URL`                       | `https://<fuse-name>.azurewebsites.net` (audience for private_key_jwt) |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true`                                        |

**General settings → Always On:** **On**. **Scale out:** **1 instance**
(in-memory state is not shared, so do not scale out). Save.

## 3. Configure the Company API app

**Startup Command:**

```
bash startup_company.sh
```

**Application settings:**

| Name                             | Value                                      |
|----------------------------------|--------------------------------------------|
| `FUSE_URL`                       | `https://<fuse-name>.azurewebsites.net`    |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true`                                      |

**Always On:** On. **Scale out:** 1 instance. Save.

## 4. Configure the Vendor app

**Startup Command:**

```
bash startup_vendor.sh
```

**Application settings:**

| Name                             | Value                                       |
|----------------------------------|---------------------------------------------|
| `FUSE_URL`                       | `https://<fuse-name>.azurewebsites.net`     |
| `COMPANY_API_URL`                | `https://<company-name>.azurewebsites.net`  |
| `VENDOR_URL`                     | `https://<vendor-name>.azurewebsites.net`   |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true`                                       |

`FUSE_URL` must be identical on Fuse and Vendor: it is the audience the vendor signs into its private_key_jwt assertion and that Fuse checks. After deploy, open the Fuse console and connect your connectors (demo company/vendor, GitHub, Azure) from the Cloud Connectors tab.
its public key. **Always On:** On. **Scale out:** 1 instance. Save.

## 5. Deploy the code to each app

In the Azure panel, for **each** of the three apps:

1. Right-click the app → **Deploy to Web App…**
2. Choose the `fuse-demo` folder as the source (the **same** folder all three
   times).
3. If it asks to run the remote build, say **yes** (this runs
   `pip install -r requirements.txt` on the server, which is why
   `SCM_DO_BUILD_DURING_DEPLOYMENT=true` is set).

The first build is slow — `jwcrypto` and `pyjwt[crypto]` compile. Watch the VS
Code output panel rather than assuming it hung.

The startup command on each app decides which service it runs.

## 6. Check it

- Open `https://<vendor-name>.azurewebsites.net/` — you should see a small JSON
  banner listing the connections it backs and the note that its private key
  never leaves the process.
- Open `https://<company-name>.azurewebsites.net/` — JSON service banner with
  the two endpoints and the required scope.
- Open `https://<fuse-name>.azurewebsites.net/` — the dashboard with the five
  seeded connections. Give the vendor ~10 seconds after deploy to register its
  key; PipelineCRM and DataDrift should then show a key (binding can be enabled).
- Flip **require binding** on PipelineCRM, then **Run breach story**. The feed
  shows the allow, the three blocked attacks, and the legacy bypass. That round
  trip proves all three apps reach each other (Fuse asks the Vendor to sign, the
  Vendor calls the Company directly, the Company calls back to Fuse for the key
  and revocation).

If a request hangs or errors, the apps probably cannot reach each other:
re-check that `COMPANY_API_URL`, `FUSE_URL`, and `VENDOR_URL` are the full
`https://…` URLs with no trailing slash, and that you saved the settings
(saving restarts the app).

## Notes and limits

- **Single instance, single worker, on purpose.** State is in memory. Do not
  scale out and do not switch the startup command to a multi-worker line, or
  revocations and the replay cache will not be shared.
- **A restart resets state.** The signing key is generated at startup, so after
  a restart, tokens issued before it no longer verify. Configure all settings
  first, then run the demo in one sitting. For production, move the key to Azure
  Key Vault and the state to a database.
- **No login on the dashboard.** Anyone with the URL can revoke connections. Add
  authentication (App Service Easy Auth is the quick path) before exposing it.
- **Cost note:** Always On needs B1 or higher. One B1 plan hosting all three
  apps is the quota-saving setup.
