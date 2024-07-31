# 🔎 AzRoleWatcher

🔔 Get notified on the **addition** or **removal** of roles and permissions in Microsoft Entra ID and Azure 🔔

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

Note that AzRoleWatcher is **run daily** around 04:00 AM Central European Time (2:00 AM UTC) to detect changes.

## ⚙️ Setting up this project against your own Entra tenant

Setting up this project against a specific tenant can be useful to include custom roles and permissions in the monitoring.

The project can be configured against a specific Entra tenant as follows:

1. Fork this project.

2. In your tenant, create a service principal with a new client secret, and take note of the following:
    1. The tenant ID associated with the service principal
    2. The service principal's application/client ID
    3. The service principal's client secret

3. Grant the following application permissions to the service principal:
    1. [`RoleManagement.Read.Directory`](https://learn.microsoft.com/en-us/graph/permissions-reference#rolemanagementreaddirectory) (required to read Entra role definitions)
    2. [`Application.Read.All`](https://learn.microsoft.com/en-us/graph/permissions-reference#applicationreadall) (required to read the definitions of application permissions)

4. In the forked project, configure a GitHub secret named `API_TOKEN_GITHUB` containing a GitHub Personal Access Token (PAT) providing the following access to the forked repository:
   - Read access to metadata
   - Read and Write access to actions and code

5. In the forked project, configure a GitHub secret with the following name and value, replacing `__PLACEHOLDER__` with the values collected in step 2:

| GitHub secret name | Value (string) | 
|---|---|
| `SP_CREDENTIALS_ENTRA` | `{"tenant_id": "__PLACEHOLDER__", "client_id": "__PLACEHOLDER__", "client_secret": "__PLACEHOLDER__"}` |

**Note**: in a tenant with a default configuration, service principals have permissions to read Azure role definitions by default. Therefore, the service principal should **not** require any additional Azure permissions.
