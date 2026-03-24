#Requires -Version 7.4
#Requires -Modules @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.12.0' }
#Requires -Modules @{ ModuleName = 'Az.Resources'; ModuleVersion = '6.0.0' }
#Requires -Modules @{ ModuleName = 'GitHub'; ModuleVersion = '0.1.0' }

<#
    .SYNOPSIS
    Sets up an Azure App Registration with a flexible federated credential for GitHub Actions.

    .DESCRIPTION
    This script performs the following end-to-end setup:
    1. Creates an Azure AD App Registration (application object).
    2. Ensures a Service Principal exists for the App Registration.
    3. Configures a flexible federated identity credential on the App Registration that trusts all
       GitHub Actions runs from any repository in the specified GitHub organization.
    4. Uses the GitHub PowerShell module to store the AZURE_CLIENT_ID, AZURE_TENANT_ID,
       and AZURE_SUBSCRIPTION_ID as organization-level secrets on the specified GitHub organization.

    Flexible federated identity credentials are only supported on application objects (App Registrations),
    not on workload identities such as User-Assigned Managed Identities. See:
    https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-flexible-federated-identity-credentials

    .EXAMPLE
    ```powershell
    ./scripts/Setup-FlexFedCred.ps1
    ```

    Runs the full setup with default values.

    .EXAMPLE
    ```powershell
    ./scripts/Setup-FlexFedCred.ps1 -AppRegistrationName 'app-custom' -GitHubOrganization 'MyOrg'
    ```

    Runs the setup with a custom app registration name and GitHub organization.

    .NOTES
    Prerequisites:
    - Az.Accounts and Az.Resources PowerShell modules installed and authenticated (`Connect-AzAccount`).
      The authenticated identity must have permission to create App Registrations and
      Service Principals in the Azure AD tenant (e.g., Application Administrator role).
    - The GitHub PowerShell module installed (`Install-Module -Name GitHub`).
    - Authenticated to GitHub with permissions to manage organization secrets (`Connect-GitHub`).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword', '',
    Justification = 'FederatedCredentialName is a resource name, not a secret.'
)]
[CmdletBinding()]
param(
    # The display name of the App Registration to create.
    [Parameter()]
    [string] $AppRegistrationName = 'app-msxorg-github',

    # The name of the federated identity credential.
    [Parameter()]
    [string] $FederatedCredentialName = 'github-msxorg-all-repos',

    # The GitHub organization name.
    [Parameter()]
    [string] $GitHubOrganization = 'MSXOrg'
)

$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'

#region Validate prerequisites
Write-Information '--- Validating prerequisites ---'

# Verify Azure PowerShell is authenticated
$azContext = Get-AzContext
if (-not $azContext) {
    throw 'Azure PowerShell is not authenticated. Run "Connect-AzAccount" first.'
}
$subscriptionId = $azContext.Subscription.Id
$tenantId = $azContext.Tenant.Id
Write-Information "  Subscription: $($azContext.Subscription.Name) ($subscriptionId)"
Write-Information "  Tenant:       $tenantId"

# Verify GitHub authentication
$ghContext = Get-GitHubContext
if (-not $ghContext) {
    throw 'Not authenticated to GitHub. Run "Connect-GitHub" first.'
}
Write-Information "  GitHub context: $($ghContext.Name)"
#endregion

#region Step 1 - Create App Registration
Write-Information ''
Write-Information '--- Step 1: Create App Registration ---'

$app = Get-AzADApplication -DisplayName $AppRegistrationName -ErrorAction SilentlyContinue | Select-Object -First 1
if ($app) {
    Write-Information "  App registration '$AppRegistrationName' already exists, skipping creation."
} else {
    Write-Information "  Creating app registration '$AppRegistrationName'..."
    $app = New-AzADApplication -DisplayName $AppRegistrationName
    Write-Information "  App registration '$AppRegistrationName' created."
}

$clientId = $app.AppId
$appObjectId = $app.Id
Write-Information "  Client ID (AppId): $clientId"
Write-Information "  Object ID:         $appObjectId"
#endregion

#region Step 2 - Ensure Service Principal exists
Write-Information ''
Write-Information '--- Step 2: Ensure Service Principal ---'

$sp = Get-AzADServicePrincipal -ApplicationId $clientId -ErrorAction SilentlyContinue
if ($sp) {
    Write-Information "  Service principal for '$AppRegistrationName' already exists, skipping creation."
} else {
    Write-Information "  Creating service principal for '$AppRegistrationName'..."
    $sp = New-AzADServicePrincipal -ApplicationId $clientId
    Write-Information "  Service principal created."
}

Write-Information "  Service Principal Object ID: $($sp.Id)"
#endregion

#region Step 3 - Create Flexible Federated Identity Credential
Write-Information ''
Write-Information '--- Step 3: Create Flexible Federated Identity Credential ---'

# Flexible FICs must be created on application objects via the Microsoft Graph API.
# New-AzADAppFederatedCredential does not support the claimsMatchingExpression property,
# so we use Invoke-AzRestMethod targeting the Microsoft Graph beta endpoint.
$graphFicBaseUri = "https://graph.microsoft.com/beta/applications/$appObjectId/federatedIdentityCredentials"

# Check if a credential with this name already exists
$existingFicResponse = Invoke-AzRestMethod -Uri "$graphFicBaseUri?`$filter=name eq '$FederatedCredentialName'" -Method GET
$existingFics = ($existingFicResponse.Content | ConvertFrom-Json).value

if ($existingFics -and $existingFics.Count -gt 0) {
    Write-Information "  Flexible federated credential '$FederatedCredentialName' already exists, skipping creation."
    $fic = $existingFics[0]
    $ficId = $fic.id
} else {
    $ficBody = @{
        name                     = $FederatedCredentialName
        issuer                   = 'https://token.actions.githubusercontent.com'
        audiences                = @('api://AzureADTokenExchange')
        claimsMatchingExpression = @{
            value           = "claims['sub'] matches 'repo:$GitHubOrganization/*'"
            languageVersion = 1
        }
    } | ConvertTo-Json -Depth 5 -Compress

    Write-Information "  Expression: claims['sub'] matches 'repo:$GitHubOrganization/*'"
    Write-Information "  Creating flexible federated credential '$FederatedCredentialName'..."

    $ficResponse = Invoke-AzRestMethod -Uri $graphFicBaseUri -Method POST -Payload $ficBody

    if ($ficResponse.StatusCode -notin 200, 201) {
        throw "Failed to create flexible federated identity credential: $($ficResponse.Content)"
    }

    $fic = $ficResponse.Content | ConvertFrom-Json
    Write-Information "  Federated credential '$($fic.name)' created successfully."
    $ficId = $fic.id
}

Write-Information "  Issuer:     $($fic.issuer)"
Write-Information "  Expression: $($fic.claimsMatchingExpression.value)"
#endregion

#region Step 4 - Store secrets on GitHub organization
Write-Information ''
Write-Information '--- Step 4: Store secrets on GitHub organization ---'

$secrets = @{
    AZURE_CLIENT_ID       = $clientId
    AZURE_TENANT_ID       = $tenantId
    AZURE_SUBSCRIPTION_ID = $subscriptionId
}

foreach ($entry in $secrets.GetEnumerator()) {
    Write-Information "  Setting secret '$($entry.Key)' on organization '$GitHubOrganization'..."
    $secretParams = @{
        Owner      = $GitHubOrganization
        Name       = $entry.Key
        Value      = $entry.Value
        Visibility = 'All'
    }
    Set-GitHubSecret @secretParams
}

Write-Information '  Organization secrets configured.'
#endregion

#region Summary
Write-Information ''
Write-Information '=== Setup Complete ==='

# Fetch the final state of the app registration
Write-Information ''
Write-Information '--- App Registration ---'
$finalApp = Get-AzADApplication -ApplicationId $clientId
[PSCustomObject]@{
    DisplayName = $finalApp.DisplayName
    AppId       = $finalApp.AppId
    ObjectId    = $finalApp.Id
} | Format-List | Out-String | ForEach-Object { Write-Information $_.TrimEnd() }

# Fetch the final state of the flexible federated identity credential
Write-Information '--- Flexible Federated Identity Credential ---'
$ficGetResponse = Invoke-AzRestMethod -Uri "$graphFicBaseUri/$ficId" -Method GET
if ($ficGetResponse.StatusCode -eq 200) {
    $finalFic = $ficGetResponse.Content | ConvertFrom-Json
    [PSCustomObject]@{
        Name       = $finalFic.name
        Issuer     = $finalFic.issuer
        Audiences  = $finalFic.audiences -join ', '
        Expression = $finalFic.claimsMatchingExpression.value
        Language   = $finalFic.claimsMatchingExpression.languageVersion
    } | Format-List | Out-String | ForEach-Object { Write-Information $_.TrimEnd() }
} else {
    Write-Warning "Could not retrieve federated credential: $($ficGetResponse.Content)"
}

Write-Information '--- GitHub Organization Secrets ---'
Write-Information "Organization:  $GitHubOrganization"
Write-Information 'Secrets set:   AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID'
Write-Information ''
Write-Information 'Next steps:'
Write-Information '  1. Assign RBAC roles to the service principal on the Azure resources you need.'
Write-Information "     Example: New-AzRoleAssignment -ObjectId $($sp.Id) -RoleDefinitionName Contributor -Scope /subscriptions/$subscriptionId"
Write-Information '  2. Use azure/login@v2 in your GitHub Actions workflows with:'
Write-Information '       client-id:       ${{ secrets.AZURE_CLIENT_ID }}'
Write-Information '       tenant-id:       ${{ secrets.AZURE_TENANT_ID }}'
Write-Information '       subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}'
#endregion
