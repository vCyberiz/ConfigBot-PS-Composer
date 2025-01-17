# Install and Import the Exchange Online Management Module if not already installed
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
}

Import-Module ExchangeOnlineManagement

# Connect to Exchange Online
try {
    $adminEmail = "engineeringid1@vcyberiz.onmicrosoft.com"
    
    # Check if already connected
    $existingSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}
    if (-not $existingSession) {
        Write-Output "Connecting to Exchange Online..."
        Connect-ExchangeOnline -UserPrincipalName $adminEmail -ShowProgress $true
    } else {
        Write-Output "Already connected to Exchange Online"
    }
} catch {
    Write-Error ("Failed to connect to Exchange Online: " + $_.Exception.Message)
    exit 1
}

# Directory to save policy files (Current Directory)
$outputDirectory = (Get-Location).Path

# Function to safely fetch and save policy with limited properties
function Get-SafePolicy {
    param (
        [string]$PolicyType,
        [string]$Command,
        [string]$OutputFile
    )
    
    try {
        Write-Output "Fetching $PolicyType..."
        # Only get specific important properties to reduce output size
        $policy = Invoke-Expression $Command | Select-Object Identity, Enabled, WhatIf, 
            PhishThresholdLevel, EnableTargetedUserProtection, EnableMailboxIntelligence, 
            EnableTargetedDomainsProtection, EnableOrganizationDomainsProtection, 
            EnableMailboxIntelligenceProtection, EnableSimilarUsersSafetyTips, 
            EnableSimilarDomainsSafetyTips, EnableUnusualCharactersSafetyTips
            
        if ($policy) {
            $policy | Format-List | Out-File -FilePath (Join-Path $outputDirectory $OutputFile) -Force
            Write-Output "Policy saved to: $OutputFile"
            return $true
        } else {
            Write-Output "No policy found for: $PolicyType"
            return $false
        }
    } catch {
        Write-Error ("Error fetching " + $PolicyType + ": " + $_.Exception.Message)
        return $false
    }
}

# Fetch and Save Policies
$policies = @(
    @{
        Type = "Anti-Phishing Policy"
        Command = "Get-AntiPhishPolicy"
        File = "AntiPhishPolicy.txt"
    }
)

$successCount = 0
foreach ($policy in $policies) {
    if (Get-SafePolicy -PolicyType $policy.Type -Command $policy.Command -OutputFile $policy.File) {
        $successCount++
    }
}

# Disconnect from Exchange Online
try {
    Disconnect-ExchangeOnline -Confirm:$false
    Write-Output "Disconnected from Exchange Online"
} catch {
    Write-Error ("Error disconnecting from Exchange Online: " + $_.Exception.Message)
}

if ($successCount -eq 0) {
    Write-Error "Failed to fetch any policies"
    exit 1
} else {
    Write-Output "Successfully fetched $successCount out of $($policies.Count) policies"
    exit 0
}
