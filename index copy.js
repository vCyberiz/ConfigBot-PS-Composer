const express = require('express');
const OpenAI = require('openai');
const cors = require('cors');
require('dotenv').config();
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const admZip = require('adm-zip');

const app = express();
const initialPort = process.env.PORT || 3978;

app.use(cors());
app.use(express.json());

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// Update the system prompt
const SYSTEM_PROMPT = `You are an AI assistant for Microsoft 365 Defender and Exchange Online PowerShell.
When users ask about policies or settings, you should:

1. Determine the correct PowerShell command based on their request
2. Common commands include:
   - Get-AntiPhishPolicy [-Identity "<name>"] | Format-List
   - Get-MalwareFilterPolicy [-Identity "<name>"] | Format-List
   - Get-SafeAttachmentPolicy [-Identity "<name>"] | Format-List
   - Get-SafeLinksPolicy [-Identity "<name>"] | Format-List
   - Get-DlpPolicy [-Identity "<name>"] | Format-List
   - Get-TransportRule [-Identity "<name>"] | Format-List

3. For specific policy queries, include the -Identity parameter
4. Always use Format-List for detailed output

Return JSON in this format:
{
  "type": "command",
  "command": "exact PowerShell command",
  "description": "what this command will show"
}

For greetings or non-policy questions, return:
{
  "type": "conversation",
  "response": "your natural response"
}`;

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

// Function to handle Exchange Online connection and command execution
async function executeExchangeCommand(command) {
  try {
    // Create a more robust connection script
    const connectScript = `
    # Import Exchange Online Module
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Output "Installing Exchange Online Management module..."
        Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
    }

    Import-Module ExchangeOnlineManagement

    # Check existing connection
    $existingSession = Get-PSSession | Where-Object {$_.ConfigurationName -eq "Microsoft.Exchange" -and $_.State -eq "Opened"}
    if (-not $existingSession) {
        Write-Output "Connecting to Exchange Online..."
        Connect-ExchangeOnline -UserPrincipalName "engineeringid1@vcyberiz.onmicrosoft.com" -ShowProgress $true
    } else {
        Write-Output "Already connected to Exchange Online"
    }

    # Execute the requested command
    Write-Output "Executing command..."
    ${command}

    # Disconnect after execution
    Disconnect-ExchangeOnline -Confirm:$false
    `;

    // Save the script to a temporary file
    const scriptPath = path.join(__dirname, 'temp_script.ps1');
    fs.writeFileSync(scriptPath, connectScript);

    return new Promise((resolve, reject) => {
      // Execute the script with proper error handling
      exec(`powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}"`, (error, stdout, stderr) => {
        // Clean up the temporary script
        fs.unlinkSync(scriptPath);

        if (error) {
          console.error(`PowerShell Error: ${error}`);
          console.error(`stderr: ${stderr}`);
          reject(error);
          return;
        }

        // Check if the output contains actual policy data
        if (!stdout.includes("Identity") && !stdout.includes("Enabled")) {
          reject(new Error("No policy data returned. Check connection and permissions."));
          return;
        }

        resolve(stdout);
      });
    });
  } catch (error) {
    console.error('Error executing Exchange command:', error);
    throw error;
  }
}

// Modify the translateToPowerShellCommand function to use OpenAI
async function translateToPowerShellCommand(message) {
  try {
    const systemPrompt = `You are a Microsoft 365 Defender and Exchange Online PowerShell expert.
    Translate the user's request into the most appropriate PowerShell command.
    Common commands include:
    - Get-AntiPhishPolicy
    - Get-MalwareFilterPolicy
    - Get-SafeAttachmentPolicy
    - Get-SafeLinksPolicy
    - Get-HostedContentFilterPolicy
    - Get-DlpPolicy
    - Get-TransportRule
    
    Return only a JSON object with:
    1. command: The PowerShell command to execute
    2. description: Brief explanation of what the command will do`;

    const completion = await openai.chat.completions.create({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message }
      ],
      model: "gpt-4",
      temperature: 0.7,
      response_format: { type: "json_object" }
    });

    const response = JSON.parse(completion.choices[0].message.content);
    return {
      command: response.command,
      description: response.description
    };
  } catch (error) {
    console.error('Error in translation:', error);
    return null;
  }
}

// Add a function to execute PowerShell commands and handle errors
async function executePowerShellCommand(command) {
  return new Promise((resolve, reject) => {
    exec(`powershell.exe -ExecutionPolicy Bypass -Command "${command}"`, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error executing PowerShell command: ${error}`);
        // Implement logic to fix the error and retry
        // This is a placeholder example
        if (stderr.includes('Access Denied')) {
          // Attempt to fix access denied error
          // Retry the command
          return executePowerShellCommand(command).then(resolve).catch(reject);
        }
        reject(error);
        return;
      }
      resolve({
        text: `PowerShell Output:\n${stdout}`,
        showDownload: false
      });
    });
  });
}

// Add a new state management for pending commands
const pendingCommands = new Map();

// Update handleMessage to use async translation
const handleMessage = async (message, userId = 'default') => {
  try {
    // Handle pending command confirmation
    const pendingCommand = pendingCommands.get(userId);
    if (pendingCommand) {
      if (message.toLowerCase() === 'yes' || message.toLowerCase() === 'run') {
        pendingCommands.delete(userId);
        console.log('Executing command:', pendingCommand.command);
        
        try {
          const result = await executeExchangeCommand(pendingCommand.command);
          
          // Analyze the results
          const analysis = await openai.chat.completions.create({
            messages: [
              { 
                role: "system", 
                content: "Analyze this policy data and provide a clear summary." 
              },
              { 
                role: "user", 
                content: `Analyze this policy data:\n${result}` 
              }
            ],
            model: "gpt-4",
            temperature: 0.7
          });

          return {
            text: `# Results\n\n${analysis.choices[0].message.content}\n\n## Raw Data\n\`\`\`powershell\n${result}\`\`\``,
            showDownload: false
          };
        } catch (execError) {
          console.error('Execution error:', execError);
          return {
            text: `Error executing command: ${execError.message}. Please try again.`,
            showDownload: false
          };
        }
      } else if (message.toLowerCase() === 'no' || message.toLowerCase() === 'cancel') {
        pendingCommands.delete(userId);
        return {
          text: "Command cancelled. What else would you like to know?",
          showDownload: false
        };
      }
    }

    // Process new message
    const completion = await openai.chat.completions.create({
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: message }
      ],
      model: "gpt-4",
      temperature: 0.7
    });

    try {
      const response = JSON.parse(completion.choices[0].message.content);
      
      if (response.type === "command") {
        // Store command for execution
        pendingCommands.set(userId, {
          command: response.command,
          description: response.description
        });

        return {
          text: `I'll help you check that.\n\n## Command to execute:\n\`\`\`powershell\n${response.command}\`\`\`\n\n## This will:\n${response.description}\n\nShould I run this command? (Yes/No)`,
          showDownload: false
        };
      } else {
        return {
          text: response.response,
          showDownload: false
        };
      }
    } catch (parseError) {
      return {
        text: completion.choices[0].message.content,
        showDownload: false
      };
    }

  } catch (error) {
    console.error('Error:', error);
    return {
      text: "I encountered an error. Please try again.",
      showDownload: false
    };
  }
};

// Add token management functions
const MAX_TOKENS = 8000; // Safe limit for GPT-4

async function handleLargeResponse(result) {
  try {
    // Split large results into chunks
    const chunks = splitIntoChunks(result, 4000); // 4000 chars per chunk
    let analyzedResults = [];

    for (const chunk of chunks) {
      const analysis = await openai.chat.completions.create({
        messages: [
          { 
            role: "system", 
            content: "Analyze this portion of policy data concisely." 
          },
          { 
            role: "user", 
            content: `Analyze this data chunk:\n${chunk}` 
          }
        ],
        model: "gpt-4",
        max_tokens: 1000, // Limit response size
        temperature: 0.7
      });
      
      analyzedResults.push(analysis.choices[0].message.content);
      
      // Wait between chunks to respect rate limits
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    return {
      text: `# Analysis Results\n\n${analyzedResults.join('\n\n')}\n\n## Summary of Available Policies\n${summarizeResults(result)}`,
      showDownload: true
    };
  } catch (error) {
    console.error('Error in handleLargeResponse:', error);
    throw error;
  }
}

function splitIntoChunks(text, chunkSize) {
  const chunks = [];
  let i = 0;
  while (i < text.length) {
    chunks.push(text.slice(i, i + chunkSize));
    i += chunkSize;
  }
  return chunks;
}

function summarizeResults(result) {
  // Extract just the policy names or key information
  const lines = result.split('\n');
  return lines
    .filter(line => line.includes('Policy'))
    .map(line => `- ${line.trim()}`)
    .join('\n');
}

// Modify the executeCommandWithRetry function
async function executeCommandWithRetry(command, maxRetries = 5) {
  try {
    console.log('Executing command:', command);
    const result = await executeExchangeCommand(command);
    
    // Check result size
    if (estimateTokens(result) > MAX_TOKENS) {
      console.log('Large response detected, using chunked processing');
      return await handleLargeResponse(result);
    }
    
    // Normal processing for smaller results
    const analysis = await openai.chat.completions.create({
      messages: [
        { 
          role: "system", 
          content: "Provide a concise summary of the policy data." 
        },
        { 
          role: "user", 
          content: `Analyze this policy data:\n${result}` 
        }
      ],
      model: "gpt-4",
      max_tokens: 1000,
      temperature: 0.7
    });

    return {
      text: `# Results\n\n${analysis.choices[0].message.content}\n\n## Raw Data\n\`\`\`powershell\n${result}\`\`\``,
      showDownload: false
    };

  } catch (error) {
    console.error('Error executing command:', error);
    throw error;
  }
}

// Helper function to estimate tokens
function estimateTokens(text) {
  // Rough estimate: 4 chars per token
  return Math.ceil(text.length / 4);
}

// Add helper functions for fixing common errors
async function attemptAccessDeniedFix() {
  try {
    // Attempt to reconnect with elevated permissions
    await executeExchangeCommand('Connect-ExchangeOnline -UserPrincipalName "engineeringid1@vcyberiz.onmicrosoft.com" -PSSessionOption $SessionOptions');
    return true;
  } catch (error) {
    console.error('Failed to fix access denied error:', error);
    return false;
  }
}

async function attemptReconnection() {
  try {
    // Force a new connection
    await executeExchangeCommand('Disconnect-ExchangeOnline -Confirm:$false; Connect-ExchangeOnline -UserPrincipalName "engineeringid1@vcyberiz.onmicrosoft.com"');
    return true;
  } catch (error) {
    console.error('Failed to reconnect:', error);
    return false;
  }
}

// Add usage monitoring
async function checkUsage() {
  try {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    
    const usage = await openai.usage.list({
      start_date: startOfMonth.toISOString().split('T')[0],
      end_date: now.toISOString().split('T')[0],
    });
    
    console.log('Current Usage:', usage);
    return usage;
  } catch (error) {
    console.error('Error checking usage:', error);
    return null;
  }
}

// Update the messages endpoint to handle user sessions
app.post('/api/messages', async (req, res) => {
  try {
    console.log('Received message:', req.body);
    
    if (!req.body.text) {
      return res.status(400).json({ error: 'Message text is required' });
    }

    // You can use session ID or user ID here if you implement user management
    const userId = 'default';
    const response = await handleMessage(req.body.text, userId);
    
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

// Update the init route message to be more general
app.get('/api/init', (req, res) => {
  res.json({
    type: 'message',
    text: 'Hello! I am your AI assistant. How can I help you today?'
  });
});

// Serve test page
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bot Test Page</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                margin: 20px; 
                max-width: 800px; 
                margin: 0 auto; 
                padding: 20px;
            }
            #chatbox { 
                border: 1px solid #ccc; 
                padding: 15px; 
                height: 400px; 
                overflow-y: auto; 
                margin-bottom: 15px; 
                border-radius: 5px;
            }
            .message {
                margin-bottom: 10px;
                padding: 8px 15px;
                border-radius: 15px;
                max-width: 80%;
                word-wrap: break-word;
                white-space: pre-wrap;
            }
            .user-message {
                background-color: #007bff;
                color: white;
                margin-left: auto;
            }
            .bot-message {
                background-color: #f1f1f1;
                margin-right: auto;
                font-family: monospace;
                line-height: 1.5;
            }
            .bot-message h1 {
                font-size: 1.5em;
                margin-top: 10px;
                margin-bottom: 10px;
                color: #333;
            }
            .bot-message h2 {
                font-size: 1.2em;
                margin-top: 8px;
                margin-bottom: 8px;
                color: #444;
            }
            .bot-message ul, .bot-message ol {
                margin-left: 20px;
                margin-bottom: 10px;
            }
            .bot-message li {
                margin-bottom: 5px;
            }
            .bot-message code {
                background-color: #e8e8e8;
                padding: 2px 4px;
                border-radius: 3px;
            }
            .input-container {
                display: flex;
                gap: 10px;
            }
            #input { 
                flex-grow: 1;
                padding: 10px; 
                border: 1px solid #ccc;
                border-radius: 5px;
            }
            button { 
                padding: 10px 20px; 
                background-color: #007bff;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
            }
            button:hover {
                background-color: #0056b3;
            }
            .download-button {
                background-color: #28a745;
                color: white;
                padding: 5px 10px;
                border-radius: 5px;
                cursor: pointer;
                display: inline-block;
                margin-top: 10px;
                text-decoration: none;
            }
            .download-button:hover {
                background-color: #218838;
            }
        </style>
    </head>
    <body>
        <div id="chatbox"></div>
        <div class="input-container">
            <input type="text" id="input" placeholder="Type a message...">
            <button onclick="sendMessage()">Send</button>
        </div>
        <script>
            const chatbox = document.getElementById('chatbox');
            const input = document.getElementById('input');

            const sendMessage = async () => {
                const message = input.value;
                if (!message) return;

                chatbox.innerHTML += \`
                    <div class="message user-message">\${message}</div>
                \`;

                const res = await fetch('/api/messages', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ text: message })
                });
                const data = await res.json();
                
                let botMessage = \`<div class="message bot-message">\${data.text}</div>\`;
                if (data.showDownload) {
                    botMessage += \`
                        <a href="/api/download-policies" class="download-button">
                            Download Policies
                        </a>
                    \`;
                }
                chatbox.innerHTML += botMessage;
                
                input.value = '';
                chatbox.scrollTop = chatbox.scrollHeight;
            };

            // Initial Greeting on Page Load
            window.onload = async () => {
                const res = await fetch('/api/init');
                const data = await res.json();
                chatbox.innerHTML = \`<div class="message bot-message">\${data.text}</div>\`;
            };
        </script>
    </body>
    </html>
  `);
});

// Start the server
app.listen(initialPort, () => {
  console.log(`Bot server running on port ${initialPort}`);
});

async function checkOpenAIAccess() {
  try {
    console.log('Checking OpenAI access levels...');
    
    // List available models
    const models = await openai.models.list();
    
    // Categorize models
    const availableModels = {
      gpt4: [],
      gpt35: [],
      other: []
    };

    models.data.forEach(model => {
      if (model.id.includes('gpt-4')) {
        availableModels.gpt4.push(model.id);
      } else if (model.id.includes('gpt-3.5')) {
        availableModels.gpt35.push(model.id);
      } else {
        availableModels.other.push(model.id);
      }
    });

    console.log('\nAccess Level Report:');
    console.log('-------------------');
    console.log('GPT-4 Models:', availableModels.gpt4.length ? availableModels.gpt4.join(', ') : 'No access');
    console.log('GPT-3.5 Models:', availableModels.gpt35.join(', '));
    
    // Test a simple API call
    const testCall = await openai.chat.completions.create({
      messages: [{ role: "user", content: "Test" }],
      model: "gpt-3.5-turbo",
      max_tokens: 5
    });

    console.log('\nAPI Status: Active');
    console.log('Default Model Working: Yes');

    return {
      hasGPT4: availableModels.gpt4.length > 0,
      models: availableModels,
      apiStatus: 'active'
    };

  } catch (error) {
    console.error('Error checking access:', error);
    
    return {
      error: error.message,
      type: error.type,
      hasGPT4: false,
      apiStatus: 'error'
    };
  }
}

// Run the check
checkOpenAIAccess().then(result => {
  console.log('\nFinal Results:', result);
}).catch(error => {
  console.error('Check failed:', error);
});
