# FlexFedCredTest

A test repository demonstrating **Microsoft Flexible Federated Identity Credentials** between GitHub Actions and Azure. This repo shows how a single federated credential can trust all GitHub Actions runs across an entire GitHub organization—without storing any secrets.

---

## What Are Flexible Federated Identity Credentials?

[Flexible Federated Identity Credentials](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials?tabs=github) are a preview feature of Microsoft Entra Workload ID that extend the classic federated credential model with **expression-based claim matching**.

### Classic vs. Flexible

| | Classic Federated Credential | Flexible Federated Credential |
|---|---|---|
| **Matching** | Exact subject match (e.g., one branch, one environment) | Expression-based matching (e.g., all repos in an org, any branch) |
| **Credentials required** | One per workflow/branch/environment combination | One credential can cover many workflows |
| **Limit per identity** | 20 credentials per app/managed identity | Significantly higher limits |
| **New claims supported** | `sub`, `iss`, `aud` only | Custom claims beyond `sub`, `iss`, `aud` |

### How It Works

1. A GitHub Actions workflow requests a short-lived **OIDC token** from GitHub's token provider (`https://token.actions.githubusercontent.com`).
2. The token contains claims such as `sub` (repository + ref), `repository`, `ref`, `workflow`, and others.
3. Azure Entra evaluates the token against the `claimsMatchingExpression` defined on the federated credential.
4. If the expression matches, Azure issues an **access token** that the workflow uses to call Azure APIs—no long-lived secret is ever stored or transmitted.

This pattern eliminates the need to rotate credentials and greatly reduces the risk of secret leakage.

---

## Repository Structure

```
FlexFedCredTest/
├── .github/
│   └── workflows/
│       └── azure-login.yml          # GitHub Actions workflow that logs in to Azure
├── scripts/
│   └── Setup-FlexFedCred.ps1        # PowerShell setup script (one-time infrastructure provisioning)
└── README.md
```

### `scripts/Setup-FlexFedCred.ps1`

A PowerShell 7 script that performs the complete end-to-end setup:

1. **Creates an Azure Resource Group** (default: `rg-msxorg-github`).
2. **Creates a User-Assigned Managed Identity** (default: `mi-msxorg-github`).
3. **Configures a Flexible Federated Identity Credential** on the managed identity with the expression:
   ```
   claims['sub'] matches 'repo:MSXOrg/*'
   ```
   This single credential trusts any GitHub Actions workflow running from any repository in the **MSXOrg** organization.
4. **Stores the required Azure secrets** (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`) as organization-level GitHub secrets so every repository in the org can consume them.

### `.github/workflows/azure-login.yml`

A GitHub Actions workflow that validates the setup by logging in to Azure using the flexible federated credential and printing Azure subscription information. It runs on every push to `main` and can also be triggered manually.

---

## Prerequisites

- **Azure**
  - An active Azure subscription.
  - The `Az` PowerShell module installed and authenticated (`Connect-AzAccount`).
- **GitHub**
  - The `GitHub` PowerShell module installed (`Install-Module -Name GitHub`).
  - Authenticated to GitHub with permissions to manage organization secrets (`Connect-GitHub`).
- **PowerShell 7.4** or later.

---

## Setup

Run the setup script once to provision all required Azure and GitHub resources:

```powershell
# Clone the repo and navigate to it
cd FlexFedCredTest

# Log in to Azure and GitHub first
Connect-AzAccount
Connect-GitHub

# Run the setup script with defaults
./scripts/Setup-FlexFedCred.ps1
```

### Optional parameters

| Parameter | Default | Description |
|---|---|---|
| `-ResourceGroupName` | `rg-msxorg-github` | Name of the Azure Resource Group to create |
| `-Location` | `swedencentral` | Azure region for all resources |
| `-ManagedIdentityName` | `mi-msxorg-github` | Name of the User-Assigned Managed Identity |
| `-FederatedCredentialName` | `github-msxorg-all-repos` | Name of the federated identity credential |
| `-GitHubOrganization` | `MSXOrg` | GitHub organization whose workflows should be trusted |

Example with custom values:

```powershell
./scripts/Setup-FlexFedCred.ps1 -ResourceGroupName 'rg-custom' -Location 'westeurope'
```

---

## Using Azure Login in Workflows

Once the setup script has run, any workflow in the organization can authenticate to Azure using the stored organization secrets:

```yaml
permissions:
  id-token: write   # Required to request the OIDC token
  contents: read

steps:
  - name: Log in to Azure
    uses: azure/login@v2
    with:
      client-id:       ${{ secrets.AZURE_CLIENT_ID }}
      tenant-id:       ${{ secrets.AZURE_TENANT_ID }}
      subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

> **Note:** The `id-token: write` permission is mandatory for OIDC-based login. Without it, GitHub will not issue an OIDC token to the workflow.

After a successful login, subsequent steps can use the Azure CLI, Azure PowerShell, or any Azure SDK directly—all backed by the managed identity's permissions.

---

## Assigning Azure Permissions

The managed identity is created with no role assignments by default. After running the setup script, grant it the roles it needs:

```powershell
New-AzRoleAssignment `
    -ObjectId    "<PrincipalId from setup output>" `
    -RoleDefinitionName Contributor `
    -Scope "/subscriptions/<SubscriptionId>"
```

Scope the role as narrowly as possible (resource group or individual resource) to follow the principle of least privilege.

---

## References

- [Flexible federated identity credentials (preview) – Microsoft Entra Workload ID](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials?tabs=github)
- [Set up a Flexible Federated Identity Credential](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-set-up-flexible-federated-identity-credential)
- [GitHub Actions: Configuring OpenID Connect in Azure](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-azure)
- [`azure/login` Action](https://github.com/Azure/login)
