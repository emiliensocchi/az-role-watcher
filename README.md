# 🔎 AzRoleWatcher

Get notified on the **addition** or **removal** of roles and permissions in Microsoft Entra ID and Azure.

### 🔔 Detected changes this year (2026) 

> last updated: 2026-04-16T04:46:00Z 

| 🏷️ Category | ➕ Added | ❌ Removed |
|----------|-------|---------|
| ☁️ Azure roles | <span style="color:#009E73;font-weight:bold">47</span> | 0 |
| 👤 Entra roles | <span style="color:#009E73;font-weight:bold">9</span> | 0 |
| 🤖 MS Graph app permissions | <span style="color:#009E73;font-weight:bold">19</span> | 0 |


## 📃 Description 

This project continously verifies if the following assets have been updated with **additions** and/or **removals** during the **last 24 hours**:
- **Azure roles**
- **Entra roles**
- **Microsoft Graph application permissions**

The latest available roles and permissions are pulled once a day from the MS Graph and ARM APIs directly, and compared to a local snapshot to detect any changes.

## 📣 How to get notified?

[Preview an example](https://www.joydeepdeb.com/misc/rss-feed-reader.html?url_id=https://raw.githubusercontent.com/emiliensocchi/az-role-watcher/main/examples/example.rss)

Point your favorite RSS reader to [`latest.rss`](https://raw.githubusercontent.com/emiliensocchi/az-role-watcher/main/latest.rss). 

The file is updated every time a change is detected and stays unmodified otherwise. This means the date of the **latest commit** corresponds to the date of the **latest addition or removal** of an Azure role, Entra role or Microsoft Graph application permission.

Note that AzRoleWatcher is **run daily** around 1:00 AM UTC to detect changes.

## ⚙️ Setting up this project against your own Entra tenant

Setting up this project against a specific tenant can be useful to include custom roles and permissions in the monitoring.

The project can be configured against a specific Entra tenant as follows:

1. Fork this project.

2. In your tenant, create a service principal with a new [Federated credential](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust?pivots=identity-wif-apps-methods-azp#github-actions), and take note of the following:
    1. The tenant ID associated with the service principal
    2. The service principal's application/client ID

3. Grant the following application permissions to the service principal:
    1. [`RoleManagement.Read.Directory`](https://learn.microsoft.com/en-us/graph/permissions-reference#rolemanagementreaddirectory) (required to read Entra role definitions)
    2. [`Application.Read.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#applicationreadall) (required to read the definitions of application permissions)

4. In the forked GitHub project, create the following repository variables:

| Name | Value | 
|---|---|
| `AZURE_TENANT_ID` | \<value-from-step-2-i\> |
| `AZURE_CLIENT_ID` | \<value-from-step-2-ii\> | 

**Note**: in a tenant with a default configuration, service principals have permissions to read Azure role definitions by default. Therefore, the service principal should **not** require any additional Azure permissions.
