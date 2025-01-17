const express = require('express');
const OpenAI = require('openai');
const cors = require('cors');
require('dotenv').config();
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const admZip = require('adm-zip');
const session = require('express-session');

// Add deployment logging
console.log('Environment:', process.env.NODE_ENV);
console.log('Port:', process.env.PORT);
console.log('Current directory:', __dirname);

const app = express();
const initialPort = process.env.PORT || 3978;

// Update CORS configuration to handle all the headers
app.use(cors({
  origin: [
    'https://sandbox-3.reactblade.portal.azure.net',
    'https://m365aichatbot.azurewebsites.net',
    'http://localhost:3000'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Origin',
    'Accept',
    'User-Agent',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'Sec-Fetch-Site',
    'Sec-Fetch-Mode',
    'Sec-Fetch-Dest',
    'Referer'
  ],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

// Add preflight handling
app.options('*', cors());

// Add headers to all responses
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', true);
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, User-Agent, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform');
  next();
});

app.use(express.json());
app.use(express.static(__dirname));
app.use('/Images', express.static(path.join(__dirname, 'Images')));

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Update the system prompt for more comprehensive AI capabilities
const SYSTEM_PROMPT = `You are an advanced AI assistant specializing in Microsoft 365 and Azure tenant management. Your capabilities include:

1. Natural Language Understanding:
   - Translate user questions into appropriate PowerShell commands
   - Understand context and intent of user queries
   - Handle follow-up questions and maintain conversation context

2. Security Analysis:
   - Analyze configurations for security best practices
   - Identify potential security risks and misconfigurations
   - Provide actionable security recommendations

3. Tenant Management:
   - Monitor and analyze tenant configurations
   - Provide insights on license usage and assignments
   - Identify optimization opportunities

4. Proactive Assistance:
   - Suggest relevant commands based on context
   - Provide preventive security recommendations
   - Highlight important settings that need attention

Always base your responses on actual data and provide specific, actionable insights.`;

// Add conversation history storage
const conversationHistory = new Map();

// Add a policy storage to the conversation history
const policyStorage = new Map();

// Add policy section definitions
const POLICY_SECTIONS = {
  OVERVIEW: 'overview',
  PHISHING_PROTECTION: 'phishing_protection',
  IMPERSONATION: 'impersonation',
  SAFETY_TIPS: 'safety_tips',
  ADVANCED: 'advanced'
};

// Modify the Get-SafePolicy function to organize data by sections
function organizeDataBySection(policyData) {
  return {
    overview: {
      title: "General Overview",
      properties: [
        'Identity',
        'Enabled',
        'WhatIf',
        'PhishThresholdLevel'
      ]
    },
    phishing_protection: {
      title: "Phishing Protection Settings",
      properties: [
        'EnableTargetedUserProtection',
        'EnableMailboxIntelligence',
        'EnableMailboxIntelligenceProtection'
      ]
    },
    impersonation: {
      title: "Impersonation Protection",
      properties: [
        'EnableTargetedDomainsProtection',
        'EnableOrganizationDomainsProtection'
      ]
    },
    safety_tips: {
      title: "Safety Tips Configuration",
      properties: [
        'EnableSimilarUsersSafetyTips',
        'EnableSimilarDomainsSafetyTips',
        'EnableUnusualCharactersSafetyTips'
      ]
    }
  };
}

// Add a function to execute PowerShell script and read outputs
const executeDefenderPolicyScript = () => {
  return new Promise((resolve, reject) => {
    const scriptPath = `"${path.join(__dirname, 'Get-DefenderPolicies.ps1')}"`;
    const command = `powershell.exe -ExecutionPolicy Bypass -File ${scriptPath}`;
    
    exec(command, async (error, stdout, stderr) => {
      console.log('PowerShell Output:', stdout);
      console.log('PowerShell Errors:', stderr);

      if (error) {
        console.error(`Error executing PowerShell script: ${error}`);
        reject(error);
        return;
      }

      try {
        // Only check for anti-phishing policy
        const policyFile = 'AntiPhishPolicy.txt';
        
        if (!fs.existsSync(policyFile)) {
          reject(new Error('Anti-phishing policy file was not created. Please check your Exchange Online credentials and permissions.'));
          return;
        }

        const policyContents = fs.readFileSync(policyFile, 'utf8');

        resolve({
          scriptOutput: stdout,
          policyContents: policyContents
        });
      } catch (err) {
        reject(err);
      }
    });
  });
};

// Add tenant configuration storage
const tenantConfigs = new Map();

// Add tenant configuration storage with file persistence
const TENANTS_FILE = path.join(__dirname, 'tenants.json');

// Function to save tenants to file
function saveTenantsToFile() {
  try {
    const tenants = Object.fromEntries(tenantConfigs);
    fs.writeFileSync(TENANTS_FILE, JSON.stringify(tenants, null, 2));
    console.log('Saved tenants to file');
  } catch (error) {
    console.error('Error saving tenants to file:', error);
  }
}

// Function to load tenants from file
function loadTenantsFromFile() {
  try {
    if (fs.existsSync(TENANTS_FILE)) {
      const data = fs.readFileSync(TENANTS_FILE, 'utf8');
      const tenants = JSON.parse(data);
      tenantConfigs.clear();
      Object.entries(tenants).forEach(([id, config]) => {
        tenantConfigs.set(id, config);
      });
      console.log('Loaded tenants from file:', tenants);
    }
  } catch (error) {
    console.error('Error loading tenants from file:', error);
  }
}

// Load tenants when server starts
loadTenantsFromFile();

// Add PowerShell session management
const activeSessions = new Map();

// Function to check if a valid session exists for a tenant
async function hasValidSession(tenantId) {
  try {
    if (!activeSessions.has(tenantId)) return false;
    
    const scriptPath = path.join(__dirname, `check_session_${Date.now()}.ps1`);
    const script = `
      $session = Get-PSSession | Where-Object {
        $_.ConfigurationName -eq "Microsoft.Exchange" -and 
        $_.State -eq "Opened" -and 
        $_.Availability -eq "Available"
      }
      if ($session) {
        Write-Output "true"
      } else {
        Write-Output "false"
      }`;
    
    fs.writeFileSync(scriptPath, script);
    const result = await new Promise((resolve, reject) => {
      exec(`powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}"`, (error, stdout) => {
        fs.unlinkSync(scriptPath);
        if (error) reject(error);
        else resolve(stdout.trim() === "true");
      });
    });
    
    return result;
  } catch (error) {
    console.error('Error checking session:', error);
    return false;
  }
}

// Update executeExchangeCommand to handle tenant switching
async function executeExchangeCommand(command, tenantInfo) {
  let scriptPath = null;
  try {
    // Create connection script with session cleanup and reconnection
    const connectScript = `
    # Function to check and establish connections
    function EnsureConnected {
      param (
        [string]$adminEmail
      )
      
      # Disconnect existing sessions first
      Get-PSSession | Where-Object {
        $_.ConfigurationName -eq "Microsoft.Exchange" -or 
        $_.ComputerName -like "*.ps.compliance.protection.outlook.com"
      } | Remove-PSSession

      # Clear any existing MSOnline connections
      [Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
      
      $msolConnected = $false
      $exchangeConnected = $false

      # Connect to MSOnline
      if (-not (Get-Module -ListAvailable -Name MSOnline)) {
        Install-Module -Name MSOnline -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
      }
      Import-Module MSOnline -ErrorAction Stop
      Connect-MsolService
      $msolConnected = $true

      # Connect to Exchange Online
      if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
      }
      Import-Module ExchangeOnlineManagement -ErrorAction Stop
      Connect-ExchangeOnline -UserPrincipalName $adminEmail -ShowBanner:$false -ShowProgress $false
      $exchangeConnected = $true

      # Connect to Security & Compliance PowerShell
      Connect-IPPSSession -UserPrincipalName $adminEmail -ShowBanner:$false

      return $msolConnected -and $exchangeConnected
    }

    # Always establish new connections when executing commands
    if (EnsureConnected -adminEmail "${tenantInfo.adminEmail}") {
      Write-Output "Session established successfully"
    } else {
      throw "Failed to establish required connections"
    }

    # Execute the actual command
    ${command}`;

    // Save the script to a temporary file with a unique name
    const timestamp = Date.now();
    scriptPath = path.join(__dirname, `temp_script_${timestamp}.ps1`);
    fs.writeFileSync(scriptPath, connectScript);

    return new Promise((resolve, reject) => {
      exec(`powershell.exe -ExecutionPolicy Bypass -NoProfile -File "${scriptPath}"`, (error, stdout, stderr) => {
        // Clean up the temporary script
        try {
          if (scriptPath && fs.existsSync(scriptPath)) {
            fs.unlinkSync(scriptPath);
          }
        } catch (cleanupError) {
          console.error('Error cleaning up temp script:', cleanupError);
        }

        if (error) {
          console.error(`PowerShell Error: ${error}`);
          console.error(`stderr: ${stderr}`);
          reject(error);
          return;
        }

        resolve(stdout);
      });
    });
  } catch (error) {
    // Ensure cleanup happens even if there's an error
    try {
      if (scriptPath && fs.existsSync(scriptPath)) {
        fs.unlinkSync(scriptPath);
      }
    } catch (cleanupError) {
      console.error('Error cleaning up temp script:', cleanupError);
    }
    
    console.error('Error executing Exchange command:', error);
    throw error;
  }
}

// Add tenant management endpoints
app.post('/api/tenant/add', (req, res) => {
  try {
    const { tenantId, tenantName, adminEmail } = req.body;
    
    if (!tenantId || !tenantName || !adminEmail) {
      return res.status(400).json({ error: 'Missing required tenant information' });
    }

    tenantConfigs.set(tenantId, {
      tenantName,
      adminEmail,
      lastConnection: null
    });

    // Save changes to file
    saveTenantsToFile();

    res.json({ 
      message: 'Tenant added successfully',
      tenantId
    });
  } catch (error) {
    console.error('Error adding tenant:', error);
    res.status(500).json({ error: 'Failed to add tenant' });
  }
});

app.get('/api/tenants', (req, res) => {
  try {
    const tenants = Array.from(tenantConfigs.entries()).map(([id, config]) => ({
      tenantId: id,
      tenantName: config.tenantName,
      adminEmail: config.adminEmail
    }));
    
    res.json({ tenants });
  } catch (error) {
    console.error('Error fetching tenants:', error);
    res.status(500).json({ error: 'Failed to fetch tenants' });
  }
});

// Function to generate PowerShell command using OpenAI
async function generatePowerShellCommand(query) {
  try {
    const commandPrompt = `Convert this request into appropriate PowerShell commands for Microsoft 365 management:
    User Query: "${query}"
    
    Consider:
    1. Use the most appropriate commands for the specific request
    2. Include necessary connection commands if specific modules are needed
    3. Format output for readability
    4. Return ONLY the PowerShell commands without any explanation or markdown
    
    For common tenant information, use commands like:
    - Get-MsolCompanyInformation
    - Get-MsolDomain
    - Get-MsolAccountSku
    - Get-MsolUser -All | Measure-Object
    
    For security information, use commands like:
    - Get-AntiPhishPolicy
    - Get-SafeLinksPolicy
    - Get-MalwareFilterPolicy
    
    For compliance information, use commands like:
    - Get-DlpCompliancePolicy
    - Get-RetentionCompliancePolicy
    - Get-Label`;

    const completion = await openai.chat.completions.create({
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: commandPrompt }
      ],
      model: "gpt-3.5-turbo",
      temperature: 0.3,
      max_tokens: 500
    });

    // Actually use the AI-generated command instead of a hardcoded template
    return completion.choices[0].message.content;
  } catch (error) {
    console.error('Error generating PowerShell command:', error);
    throw error;
  }
}

// Update handleMessage to use AI for command generation
const handleMessage = async (message, userId = 'default', tenantId = null) => {
  try {
    // Check if message contains tenant selection
    if (message.toLowerCase().includes('select tenant')) {
      const tenants = Array.from(tenantConfigs.entries()).map(([id, config]) => 
        `• ${config.tenantName} (ID: ${id})`
      );
      
      return {
        text: `# Available Tenants\nPlease select a tenant by replying with its ID:\n\n${tenants.join('\n')}`,
        requireTenantSelection: true
      };
    }

    // If no tenant is selected and we have multiple tenants, ask to select one
    if (!tenantId && tenantConfigs.size > 0) {
      return {
        text: "Please select a tenant first by typing 'select tenant'",
        showDownload: false
      };
    }

    // Handle DLP policy queries
    const dlpQuery = message.toLowerCase();
    if (dlpQuery.includes('dlp') || 
        dlpQuery.includes('data loss') ||
        (dlpQuery.includes('data') && dlpQuery.includes('prevention')) ||
        (dlpQuery.includes('compliance') && dlpQuery.includes('polic'))) {
      
      const command = [
        '# Ensure required modules are available and connected',
        'if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {',
        '    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser',
        '}',
        'Import-Module ExchangeOnlineManagement',
        '',
        '# Get DLP policies with detailed information',
        '$policies = Get-DlpCompliancePolicy',
        'if ($policies) {',
        '    $policies | Select-Object Name, Mode, Priority,',
        '        @{Name="Workloads";Expression={$_.WorkLoadNames -join ", "}},',
        '        @{Name="Status";Expression={$_.Enabled}},',
        '        @{Name="Rules";Expression={',
        '            (Get-DlpComplianceRule -Policy $_.Name | Select-Object -ExpandProperty Name) -join ", "',
        '        }} | Format-List',
        '',
        '    Write-Output "`nDetailed DLP Rules:`n"',
        '    foreach ($policy in $policies) {',
        '        Write-Output "Policy: $($policy.Name)"',
        '        Get-DlpComplianceRule -Policy $policy.Name |',
        '            Select-Object Name,',
        '                @{Name="ContentTypes";Expression={$_.ContentTypes -join ", "}},',
        '                @{Name="Conditions";Expression={$_.ContentContainsSensitiveInformation.Name -join ", "}},',
        '                Disabled |',
        '            Format-List',
        '        Write-Output "------------------------"',
        '    }',
        '} else {',
        '    Write-Output "No DLP policies found in the tenant."',
        '}'
      ].join('\n');

      const tenantInfo = tenantConfigs.get(tenantId);
      return {
        text: `# Command Preview\nTenant: ${tenantInfo ? tenantInfo.tenantName : 'Default'}\n\nI'll retrieve your DLP (Data Loss Prevention) policies and rules using this command:\n\`\`\`powershell\n${command}\`\`\`\n\nWould you like me to proceed?`,
        requireConfirmation: true,
        command: command,
        tenantId: tenantId
      };
    }

    // Handle greetings first
    const greetings = ['hi', 'hello', 'hey', 'good morning', 'good afternoon', 'good evening'];
    if (greetings.some(greeting => message.toLowerCase().trim() === greeting)) {
      let suggestionText = '';
      
      try {
        // Try to get AI-suggested commands
        const suggestions = await suggestCommands("Initial greeting, new session");
        if (suggestions && suggestions.length > 0) {
          suggestionText = suggestions.map(s => `• ${s.command} - ${s.purpose}`).join('\n');
        }
      } catch (error) {
        console.error('Error getting AI suggestions:', error);
      }

      // If AI suggestions failed, use default suggestions
      if (!suggestionText) {
        suggestionText = `• Get-MsolAccountSku - View license information and usage
• Get-MsolUser - View user accounts and their properties
• Get-MsolCompanyInformation - View tenant details
• Get-AntiPhishPolicy - View phishing protection settings
• Get-MsolDomain - View domain information`;
      }

          return {
        text: "Hello! I can help you manage and analyze your Microsoft 365 tenant.\n\n" +
              "Here are some useful commands you can try:\n\n" +
              suggestionText + "\n\n" +
              "Feel free to ask me anything about your tenant's configuration or security!",
            showDownload: false
          };
    }

    // Update the command generation for license queries
    const licenseQuery = message.toLowerCase();
    if (licenseQuery.includes('defender') && licenseQuery.includes('license')) {
      const command = [
        '# Ensure MSOnline module is available and connected',
        'if (-not (Get-Module -ListAvailable -Name MSOnline)) {',
        '    Install-Module -Name MSOnline -Force -AllowClobber -Scope CurrentUser',
        '}',
        'Import-Module MSOnline',
        '',
        '# Connect to MSOnline if not already connected',
        'try {',
        '    Get-MsolDomain -ErrorAction Stop | Out-Null',
        '} catch {',
        '    Connect-MsolService',
        '}',
        '',
        '# Get Defender licenses',
        'Write-Output "=== Microsoft Defender Licenses ===`n"',
        '$licenses = Get-MsolAccountSku | Where-Object { ',
        '    $_.AccountSkuId -like "*defender*" -or ',
        '    $_.ServiceStatus.ServicePlan.ServiceName -like "*defender*" -or ',
        '    $_.AccountSkuId -like "*EMS*" -or ',
        '    $_.AccountSkuId -like "*E5*"',
        '}',
        '',
        'if ($licenses) {',
        '    foreach ($license in $licenses) {',
        '        Write-Output ("License: " + $license.AccountSkuId)',
        '        Write-Output ("Total Units: " + $license.ActiveUnits)',
        '        Write-Output ("Used Units: " + $license.ConsumedUnits)',
        '        Write-Output ("Available Units: " + ($license.ActiveUnits - $license.ConsumedUnits))',
        '        Write-Output "`nDefender Services:"',
        '        $license.ServiceStatus | Where-Object {',
        '            $_.ServicePlan.ServiceName -like "*defender*" -or',
        '            $_.ServicePlan.ServiceName -like "*atp*" -or',
        '            $_.ServicePlan.ServiceName -like "*protection*"',
        '        } | ForEach-Object {',
        '            Write-Output ("- " + $_.ServicePlan.ServiceName + ": " + $_.ProvisioningStatus)',
        '        }',
        '        Write-Output "------------------------"',
        '    }',
        '} else {',
        '    Write-Output "No Microsoft Defender licenses found in the tenant."',
        '}'
      ].join('\n');

      const tenantInfo = tenantConfigs.get(tenantId);
          return {
        text: `# Command Preview\nTenant: ${tenantInfo ? tenantInfo.tenantName : 'Default'}\n\nI'll check your Microsoft Defender licenses using this command:\n\`\`\`powershell\n${command}\`\`\`\n\nWould you like me to proceed?`,
        requireConfirmation: true,
        command: command,
        tenantId: tenantId
      };
    }

    // Handle Purview-related queries
    const purviewQuery = message.toLowerCase();
    if (purviewQuery.includes('purview') || 
        (purviewQuery.includes('information governance') && purviewQuery.includes('compliance'))) {
      const command = [
        '# Ensure required modules are available and connected',
        'if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {',
        '    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser',
        '}',
        'Import-Module ExchangeOnlineManagement',
        '',
        '# Connect to Security & Compliance PowerShell if not already connected',
        '$securitySession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}',
        'if (-not $securitySession) {',
        '    Connect-IPPSSession -ShowBanner:$false',
        '}',
        '',
        'Write-Output "=== Microsoft Purview Information ===`n"',
        '',
        'Write-Output "1. Data Loss Prevention (DLP) Policies:`n"',
        'Get-DlpCompliancePolicy | Select-Object Name, Mode, Priority, Enabled | Format-List',
        '',
        'Write-Output "`n2. Retention Policies:`n"',
        'Get-RetentionCompliancePolicy | Select-Object Name, Enabled, Mode | Format-List',
        '',
        'Write-Output "`n3. Sensitivity Labels:`n"',
        'Get-Label | Select-Object DisplayName, ContentType, Settings, Enabled | Format-List',
        '',
        'Write-Output "`n4. Information Protection:`n"',
        'Get-InformationProtectionPolicy | Select-Object Name, Priority, Mode | Format-List',
        '',
        'Write-Output "`n5. Data Classification:`n"',
        'Get-DlpSensitiveInformationType | Select-Object Name, Publisher, Description | Format-List',
        '',
        'Write-Output "`n6. Compliance Search Status:`n"',
        'Get-ComplianceSearch | Select-Object Name, Status, LastStartTime, ItemCount | Format-List'
      ].join('\n');

      const tenantInfo = tenantConfigs.get(tenantId);
        return {
        text: `# Command Preview\nTenant: ${tenantInfo ? tenantInfo.tenantName : 'Default'}\n\nI'll retrieve comprehensive Microsoft Purview information using this command:\n\`\`\`powershell\n${command}\`\`\`\n\nWould you like me to proceed?`,
        requireConfirmation: true,
        command: command,
        tenantId: tenantId
      };
    }

    // Add resource query handler
    const resourceQuery = message.toLowerCase();
    if (resourceQuery.includes('resource') || 
        resourceQuery.includes('how many') || 
        resourceQuery.includes('usage')) {
      const command = [
        '# Ensure required modules are available and connected',
        'if (-not (Get-Module -ListAvailable -Name MSOnline)) {',
        '    Install-Module -Name MSOnline -Force -AllowClobber -Scope CurrentUser',
        '}',
        'Import-Module MSOnline',
        '',
        '# Connect to MSOnline if not already connected',
        'try {',
        '    Get-MsolDomain -ErrorAction Stop | Out-Null',
        '} catch {',
        '    Connect-MsolService',
        '}',
        '',
        'Write-Output "=== Tenant Resource Summary ===`n"',
        '',
        'Write-Output "1. License Information:`n"',
        'Get-MsolAccountSku | Select-Object AccountSkuId, ActiveUnits, ConsumedUnits,',
        '    @{Name="AvailableUnits";Expression={$_.ActiveUnits - $_.ConsumedUnits}} | Format-List',
        '',
        'Write-Output "`n2. User Resources:`n"',
        '$users = Get-MsolUser -All',
        'Write-Output "Total Users: $($users.Count)"',
        'Write-Output "Licensed Users: $($users | Where-Object {$_.IsLicensed} | Measure-Object | Select-Object -ExpandProperty Count)"',
        'Write-Output "Admin Users: $($users | Where-Object {$_.StrongAuthenticationRequirements} | Measure-Object | Select-Object -ExpandProperty Count)"',
        '',
        'Write-Output "`n3. Domain Resources:`n"',
        'Get-MsolDomain | Select-Object Name, Status, Authentication | Format-List',
        '',
        'Write-Output "`n4. Service Status:`n"',
        'Get-MsolCompanyInformation | Select-Object @{Name="TechnicalNotificationEmails";Expression={$_.TechnicalNotificationEmails -join ", "}},',
        '    UsersPermissionToCreateGroupsEnabled,',
        '    UsersPermissionToCreateLOBAppsEnabled,',
        '    UsersPermissionToReadOtherUsersEnabled,',
        '    SelfServePasswordResetEnabled | Format-List'
      ].join('\n');

      const tenantInfo = tenantConfigs.get(tenantId);
      return {
        text: `# Command Preview\nTenant: ${tenantInfo ? tenantInfo.tenantName : 'Default'}\n\nI'll gather comprehensive resource information using this command:\n\`\`\`powershell\n${command}\`\`\`\n\nWould you like me to proceed?`,
        requireConfirmation: true,
        command: command,
        tenantId: tenantId
      };
    }

    // Handle Defender threat policy queries
    const defenderQuery = message.toLowerCase();
    if (defenderQuery.includes('defender') && 
        (defenderQuery.includes('threat') || defenderQuery.includes('policy') || defenderQuery.includes('policies'))) {
      const command = [
        '# Ensure required modules are available and connected',
        'if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {',
        '    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser',
        '}',
        'Import-Module ExchangeOnlineManagement',
        '',
        '# Connect to Security & Compliance PowerShell if not already connected',
        '$securitySession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}',
        'if (-not $securitySession) {',
        '    Connect-IPPSSession -ShowBanner:$false',
        '}',
        '',
        'Write-Output "=== Microsoft Defender Threat Policies ===`n"',
        '',
        'Write-Output "1. Anti-Malware Policies:`n"',
        'Get-MalwareFilterPolicy | Select-Object Name, Action, EnableFileFilter, ZapEnabled | Format-List',
        '',
        'Write-Output "`n2. Safe Attachments Policies:`n"',
        'Get-SafeAttachmentPolicy | Select-Object Name, Action, Enable, ActionOnError | Format-List',
        '',
        'Write-Output "`n3. Safe Links Policies:`n"',
        'Get-SafeLinksPolicy | Select-Object Name, IsEnabled, ScanUrls, EnableForInternalSenders | Format-List',
        '',
        'Write-Output "`n4. Anti-Phishing Policies:`n"',
        'Get-AntiPhishPolicy | Select-Object Name, Enabled, PhishThresholdLevel, EnableTargetedUserProtection | Format-List',
        '',
        'Write-Output "`n5. Defender for Office 365 Policies:`n"',
        'Get-ATPProtectionPolicyRule | Select-Object Name, State, Priority, Comments | Format-List'
      ].join('\n');

      const tenantInfo = tenantConfigs.get(tenantId);
      return {
        text: `# Command Preview\nTenant: ${tenantInfo ? tenantInfo.tenantName : 'Default'}\n\nI'll retrieve your Microsoft Defender threat policies using this command:\n\`\`\`powershell\n${command}\`\`\`\n\nWould you like me to proceed?`,
        requireConfirmation: true,
        command: command,
        tenantId: tenantId
      };
    }

    // Update the command generation for all queries
    if (!message.toLowerCase().startsWith('get-') && 
        !message.toLowerCase().startsWith('search-')) {
      try {
        const command = await generatePowerShellCommand(message);
        const tenantInfo = tenantConfigs.get(tenantId);

        return {
          text: `# Command Preview\nTenant: ${tenantInfo ? tenantInfo.tenantName : 'Default'}\n\nI'll help you with your request using this command:\n\`\`\`powershell\n${command}\`\`\`\n\nWould you like me to proceed?`,
          requireConfirmation: true,
          command: command,
          tenantId: tenantId
        };
      } catch (error) {
        console.error('Error generating command:', error);
        return {
          text: "I'm having trouble understanding your request. Could you try:\n\n" +
                "• Being more specific about what you want to see\n" +
                "• Using different wording\n" +
                "• Using a direct PowerShell command\n\n" +
                "For example:\n" +
                "• 'Show me our Defender licenses'\n" +
                "• 'List all users'\n" +
                "• 'Get-MsolUser'",
          showDownload: false
        };
      }
    }

    // Handle direct PowerShell commands
    if (message.toLowerCase().startsWith('get-') || 
        message.toLowerCase().startsWith('search-')) {
      const tenantInfo = tenantConfigs.get(tenantId);
      return {
        text: `# Command Preview\nTenant: ${tenantInfo ? tenantInfo.tenantName : 'Default'}\n\nI'll execute this PowerShell command:\n\`\`\`powershell\n${message}\`\`\`\n\nWould you like me to proceed?`,
        requireConfirmation: true,
        command: message,
        tenantId: tenantId
      };
    }

    // Handle other messages as questions/requests
    return {
      text: "I understand you're asking about your Microsoft 365 environment. I can help you with:\n\n" +
            "• License information (e.g., 'show me our Defender licenses')\n" +
            "• User management (e.g., 'show me all users')\n" +
            "• Security settings (e.g., 'show me security policies')\n" +
            "• Domain information (e.g., 'show me our domains')\n\n" +
            "You can also use PowerShell commands directly like Get-MsolAccountSku.",
      showDownload: false
    };

  } catch (error) {
    console.error('Error:', error);
    return {
      text: "I encountered an error while processing your request. Please try again.",
      showDownload: false
    };
  }
};

// Add security analysis function
async function analyzeSecurityImplications(output, command) {
  try {
    const securityPrompt = `Analyze this PowerShell command output for security implications:
    Command: ${command}
    Output: ${output}
    
    Consider:
    1. Security risks or concerns
    2. Compliance implications
    3. Best practice recommendations
    
    Keep the response concise and focused on security aspects.`;

      const analysis = await openai.chat.completions.create({
        messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: securityPrompt }
      ],
      model: "gpt-3.5-turbo",
      temperature: 0.7,
      max_tokens: 500
    });

    return analysis.choices[0].message.content;
  } catch (error) {
    console.error('Error analyzing security implications:', error);
    return "Unable to analyze security implications at this time.";
  }
}

// Add command suggestion function
async function suggestCommands(context) {
  try {
    const suggestPrompt = `Based on this context: "${context}"
    Suggest 3 relevant PowerShell commands that would be helpful to run next.
    For each command, explain its purpose in one short sentence.
    Return the suggestions in this format:
    [
      {"command": "Command1", "purpose": "Purpose1"},
      {"command": "Command2", "purpose": "Purpose2"},
      {"command": "Command3", "purpose": "Purpose3"}
    ]`;

    const suggestions = await openai.chat.completions.create({
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: suggestPrompt }
      ],
      model: "gpt-3.5-turbo",
      temperature: 0.7,
      max_tokens: 500
    });

    try {
      return JSON.parse(suggestions.choices[0].message.content);
    } catch (parseError) {
      console.error('Error parsing suggestions:', parseError);
      return [];
    }
  } catch (error) {
    console.error('Error getting command suggestions:', error);
    return [];
  }
}

// Update the execute-command endpoint to handle errors better
app.post('/api/execute-command', async (req, res) => {
  try {
    const { command, tenantId } = req.body;
    
    if (!command) {
      return res.status(400).json({ error: 'Command is required' });
    }

    const tenantInfo = tenantConfigs.get(tenantId) || { 
      tenantName: 'Default',
      adminEmail: 'engineeringid1@vcyberiz.onmicrosoft.com'
    };

    try {
      const commandOutput = await executeExchangeCommand(command, tenantInfo);
      
      // Store the raw command output in session
      req.session.lastCommandOutput = commandOutput;
      
      if (!commandOutput || commandOutput.trim() === '') {
        return res.json({
          text: "# No Data\nThe command executed successfully but returned no data.",
          showDownload: false
        });
      }

      // For simple list commands, just show the output
      if (command.toLowerCase().includes('get-msoluser') || 
          command.toLowerCase().includes('measure-object')) {
        return res.json({
          text: `# List\n\`\`\`powershell\n${commandOutput}\`\`\``,
          showDownload: true,
          rawOutput: commandOutput
        });
      }

      // For other Get- commands, perform analysis
      if (command.toLowerCase().startsWith('get-')) {
        const [configAnalysis, securityAnalysis] = await Promise.all([
          openai.chat.completions.create({
            messages: [
              { role: "system", content: SYSTEM_PROMPT },
              { role: "user", content: `Analyze this output:\n${commandOutput}` }
            ],
            model: "gpt-3.5-turbo",
            temperature: 0.7,
            max_tokens: 500
          }),
          analyzeSecurityImplications(commandOutput, command)
        ]);

        return res.json({
          text: `# Analysis Results\n\n## Configuration Analysis\n${configAnalysis.choices[0].message.content}\n\n` +
                `## Security Analysis\n${securityAnalysis}\n\n` +
                `## Raw Output\n\`\`\`powershell\n${commandOutput}\`\`\``,
          showDownload: true,
          rawOutput: commandOutput
        });
      }

      // For non-Get commands, just show the output
      return res.json({
        text: `# Command Output\n\`\`\`powershell\n${commandOutput}\`\`\``,
        showDownload: true,
        rawOutput: commandOutput
      });
  } catch (error) {
      console.error('Error executing command:', error);
      return res.json({
        text: `# Error\n\nFailed to execute command for tenant ${tenantInfo.tenantName}:\n${error.message}\n\nPlease ensure:\n` +
              "1. You have the MSOnline module installed\n" +
              "2. Your credentials are correct\n" +
              "3. You have the necessary permissions\n" +
              "4. The command syntax is correct",
        showDownload: false
      });
    }
  } catch (error) {
    console.error('Error processing command:', error);
    res.status(500).json({ error: 'Error processing command', details: error.message });
  }
});

// Update the messages endpoint to handle user sessions and tenant ID
app.post('/api/messages', async (req, res) => {
  try {
    console.log('Received message:', req.body);
    
    if (!req.body.text) {
      return res.status(400).json({ error: 'Message text is required' });
    }

    // Get tenantId from request body
    const userId = 'default';
    const tenantId = req.body.tenantId;
    const response = await handleMessage(req.body.text, userId, tenantId);
    
    res.json({ 
      type: 'message',
      ...response
    });
  } catch (error) {
    console.error('Error processing message:', error);
    res.status(500).json({ 
      error: 'Error processing message',
      details: error.message 
    });
  }
});

// Update the init route message to be more informative
app.get('/api/init', (req, res) => {
  console.log('Init route called');
  try {
    res.json({
      type: 'message',
      text: `# Welcome to the Microsoft 365 Management Assistant! 👋

To get started:
1. Use the dropdown above to select your tenant
2. If your tenant isn't listed, click "Add New Tenant" to add it

I can help you with:
• License management and analysis
• Security settings and policies
• User management
• Domain configuration
• And more!

You can:
• Ask questions in natural language (e.g., "show me our defender licenses")
• Use PowerShell commands directly (e.g., Get-MsolAccountSku)
• Type 'help' anytime to see more commands

Please select your tenant to begin!`
    });
  } catch (error) {
    console.error('Error in init route:', error);
    res.status(500).json({ error: 'Failed to initialize', details: error.message });
  }
});

// Add a new endpoint to handle file downloads
app.get('/api/download-policies', (req, res) => {
  try {
    const zipFile = new admZip();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const outputFileName = `m365-output-${timestamp}.txt`;

    // Create a file with the last command output
    if (req.session && req.session.lastCommandOutput) {
      fs.writeFileSync(outputFileName, req.session.lastCommandOutput);
      zipFile.addLocalFile(outputFileName);
      
      // Clean up the temporary file
      fs.unlinkSync(outputFileName);
      } else {
      // If no output is available, create a simple text file explaining that
      const noDataMessage = "No command output data is available for download.";
      fs.writeFileSync(outputFileName, noDataMessage);
      zipFile.addLocalFile(outputFileName);
      
      // Clean up the temporary file
      fs.unlinkSync(outputFileName);
    }

    const zipBuffer = zipFile.toBuffer();

    // Set headers for download
    res.set('Content-Type', 'application/zip');
    res.set('Content-Disposition', `attachment; filename=m365-data-${timestamp}.zip`);
    res.set('Content-Length', zipBuffer.length);

    res.send(zipBuffer);
  } catch (error) {
    console.error('Error creating zip file:', error);
    res.status(500).json({ error: 'Error creating download file' });
  }
});

// Add endpoint to remove tenant
app.delete('/api/tenant/:tenantId', (req, res) => {
  try {
    const { tenantId } = req.params;
    
    if (tenantConfigs.has(tenantId)) {
      tenantConfigs.delete(tenantId);
      saveTenantsToFile();
      res.json({ message: 'Tenant removed successfully' });
    } else {
      res.status(404).json({ error: 'Tenant not found' });
    }
  } catch (error) {
    console.error('Error removing tenant:', error);
    res.status(500).json({ error: 'Failed to remove tenant' });
  }
});

// Serve test page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Add a console log to verify deployment
app.post('/chat', async (req, res) => {
  try {
    console.log('Chat request received at:', new Date().toISOString());
    console.log('User message:', req.body.message);
    
    // ... rest of your chat logic ...

  } catch (error) {
    console.error('Error in chat endpoint:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Update server startup
const startServer = (port) => {
  try {
    const server = app.listen(port, () => {
      console.log(`Server started successfully on port ${port}`);
      console.log('Server timestamp:', new Date().toISOString());
    }).on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.log(`Port ${port} is busy, trying ${port + 1}...`);
        startServer(port + 1);
      } else {
        console.error('Server error:', err);
      }
    });

    // Add error handling for the server
    server.on('error', (error) => {
      console.error('Server error occurred:', error);
    });

    // Add connection handling
    server.on('connection', (socket) => {
      console.log('New connection established');
      socket.on('error', (error) => {
        console.error('Socket error:', error);
      });
    });
  } catch (error) {
    console.error('Failed to start server:', error);
  }
};

startServer(initialPort);