# AI-Assisted Infrastructure Access Architecture

**Project:** THE.WIRED Active Directory Detection Lab  
**Environment:** VMware Workstation / Windows Server / Windows 11 / Ubuntu Linux  
**AI Tool:** OpenAI Codex  
**Remote Administration:** SSH and PowerShell Remoting (WinRM)  
**Primary Objective:** Enable authorized AI-assisted diagnostics and detection engineering without publishing credentials  
**Implementation Date:** November 2026  
**Status:** Implemented in a non-production lab; additional security hardening planned

---

## 1. Executive Summary

This document describes how I integrated Codex into my existing VMware Workstation cybersecurity homelab to perform infrastructure diagnostics, validate security telemetry, and assist with detection engineering.

The environment contained three primary virtual machines:

- Windows Server — Active Directory Domain Controller
- Windows 11 — Domain-joined security testing workstation
- Ubuntu Linux — Elasticsearch, Kibana, and Fleet

Initially, these systems were primarily administered through the VMware console.

To enable more efficient AI-assisted investigations, I established authenticated remote administration paths using SSH and PowerShell Remoting.

The design emphasized:

- Discovering existing infrastructure before changing configurations.
- Keeping passwords out of chat messages and public repositories.
- Using SSH key authentication for Linux administration.
- Restricting Windows remoting connectivity to the intended lab network.
- Requesting approval before significant configuration changes.
- Preserving existing system settings where possible.
- Verifying commands and results against actual system behavior.

This implementation demonstrated controlled remote access but was not a fully least-privilege or production-hardened AI execution environment.

## 2. Architecture

```text
Physical Windows Workstation
│
├── VMware Workstation
│   │
│   └── THE.WIRED Laboratory
│       │
│       ├── Windows Server
│       │   ├── Active Directory
│       │   ├── DNS
│       │   └── Security Auditing
│       │
│       ├── Windows 11
│       │   ├── Sysmon
│       │   ├── Windows Event Logs
│       │   └── Elastic Agent
│       │
│       └── Ubuntu Linux
│           ├── Elasticsearch
│           ├── Kibana
│           └── Fleet
│
└── Codex-Assisted Administrative Workflow
    │
    ├── SSH Key Authentication
    │   └── Ubuntu Linux
    │
    ├── PowerShell Remoting / WinRM
    │   ├── Windows Server
    │   └── Windows 11
    │
    └── Elastic Management
        ├── Kibana
        └── Fleet
```

The remote commands were executed through locally accessible management interfaces and authorized remote sessions.

The Windows host and virtual machines were not directly exposed to the public internet for the purpose of this workflow.

However, additional NAT and guest-network interfaces existed. The initial inventory did not establish complete network isolation.

## 3. Initial Infrastructure Discovery

Before configuring remote access, Codex assisted with inspecting the existing VMware environment.

### Discovered Components

| Component | Finding |
|---|---|
| VMware Workstation | Version 17.6.4 |
| Domain Controller | Existing Windows Server VM |
| Workstation | Existing Windows 11 VM |
| SIEM server | Existing Ubuntu VM |
| VMware networking | Host-only and additional virtual networks |
| VM configuration | Existing VMX files accessible |
| Snapshot availability | Limited or unverified |
| VMware management | Workstation utilities available |

The initial inspection did not require creating new virtual machines or rebuilding the environment.

### Network Considerations

The primary lab communication path used a VMware host-only virtual network.

Additional NAT and network adapters were identified.

These presented potential outbound connectivity paths and required consideration when enabling remote administration.

The design goal was to restrict administrative access to known lab interfaces rather than broadly exposing management services.

## 4. Ubuntu — SSH Key Authentication

### Objective

Provide authenticated remote shell access to the Ubuntu SIEM server without supplying its account password to Codex through conversation messages.

### Initial Checks

Inside the Ubuntu VM, the following commands were used:

```bash
whoami
systemctl is-active ssh
```

The SSH service was confirmed active.

### Authentication Configuration

A dedicated Ed25519 SSH key pair was created for the lab workflow.

The public key was added to the Ubuntu account's authorized keys.

Example:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh

touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

The actual public key was installed in `~/.ssh/authorized_keys`.

Existing authorized keys were preserved.

### Host Identity Verification

The Ubuntu SSH server's host-key fingerprint was inspected:

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

The client-side connection was checked against the expected fingerprint.

After an initial client-side authentication problem was corrected, key-based SSH access succeeded.

### Result

Codex-assisted diagnostics could access Ubuntu using the dedicated SSH identity without requiring its account password in chat.

The remote account retained its existing permissions.

**Security limitation:** SSH key authentication protects credential handling but does not independently limit which commands an authenticated account may execute.

A dedicated restricted account would provide a stronger long-term boundary.

## 5. Windows — PowerShell Remoting

### Objective

Enable authorized remote diagnostics of the Domain Controller and Windows 11 workstation.

### Initial Findings

The Domain Controller already had Windows Remote Management running.

The Windows 11 workstation did not.

The Windows 11 VM also had multiple network adapters, including a domain-authenticated lab interface and another interface using a different network profile.

This required care when configuring inbound management access.

### Windows 11 Configuration

After explicit approval, WinRM was started and configured for automatic startup.

```powershell
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
```

Basic authentication and unencrypted message access were disabled:

```powershell
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
```

A Windows Defender Firewall rule was created to restrict access to:

- TCP port 5985
- The designated lab network interface
- The Domain network profile
- The Windows host's lab address
- The Windows 11 lab address

### Example Firewall Policy

The following illustrates the intended restrictions using documentation-only addresses:

```powershell
New-NetFirewallRule `
    -Name 'LAB-WinRM-FromHost' `
    -DisplayName 'Lab WinRM from management host' `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 5985 `
    -LocalAddress '192.0.2.20' `
    -RemoteAddress '192.0.2.10' `
    -InterfaceAlias 'Ethernet1' `
    -Profile Domain
```

The addresses above are placeholders, not the actual lab configuration.

This example illustrates the firewall scope rather than serving as a drop-in deployment command.

### Security Considerations

WinRM over HTTP using Negotiate authentication can provide message-level encryption, but TrustedHosts does not provide the same server-identity assurance as a properly validated HTTPS certificate.

The implementation was restricted to the lab network and requires additional identity and access hardening before it could be considered suitable for a production environment.

## 6. Windows Credential Handling

### Objective

Authenticate to Windows systems without pasting passwords into conversation messages or storing plaintext credentials in project documentation.

### Local Credential Prompt

Windows credentials were entered through PowerShell's credential prompt:

```powershell
$cred = Get-Credential `
    -Message 'Enter authorized lab credentials'
```

### Remote Authentication Test

Authenticated remoting was verified with commands equivalent to:

```powershell
Invoke-Command `
    -ComputerName 'lab-server.example.test' `
    -Authentication Negotiate `
    -Credential $cred `
    -ScriptBlock {
        hostname
        whoami
    }
```

The actual lab connection used the assigned internal addresses.

The successful results confirmed that commands could be executed remotely on both Windows virtual machines.

### Protected Credential Storage

For subsequent diagnostics, a PowerShell credential object was exported locally using `Export-Clixml` under the same Windows user context.

On Windows, this uses user- and machine-bound data protection for the credential data.

The exported file remained sensitive because processes running under the authorized Windows identity could potentially recover and use the credential.

It was not intended for publication or distribution.

### Important Limitation

The initial authenticated workflow used a Domain Administrator account.

This provided broad privileges and therefore did not meet the principle of least privilege.

A future implementation should replace this with dedicated automation accounts limited to specific administrative functions.

## 7. Correcting Execution-Context Errors

One notable problem occurred when host-side setup commands were initially executed inside the Windows 11 VM rather than on the physical Windows host.

This caused confusion when a credential export referenced a directory that existed only in the physical host's workspace.

The issue was identified by checking:

```powershell
hostname
whoami
$env:USERPROFILE
```

The workflow was corrected to run the required commands under the intended Windows host account.

An unnecessary TrustedHosts modification on Windows 11 was subsequently restored from backup.

### Lesson Learned

In environments containing a physical host, nested virtual machines, remote sessions, and AI-assisted tools, identifying the execution context is essential.

Commands that appear correct can affect the wrong machine if the current session is not verified.

## 8. Human Approval and Change Management

The original operating instructions required inspection before modification.

Significant changes were subject to user approval.

Examples included:

| Change | Approval Approach |
|---|---|
| Creating a dedicated SSH identity | Explicit approval |
| Enabling WinRM on Windows 11 | Explicit approval |
| Modifying host remoting trust | Explicit approval |
| Powering on virtual machines | Explicit approval |
| Changing DC auditing and event collection | Explicit approval |
| Installing or enrolling Elastic Agent | Approved as part of telemetry integration |
| Creating an Elastic detection rule | Performed during the requested detection engineering workflow |
| Interactive screen control | User subsequently requested explicit permission before each use |

This was a human-supervised workflow, not unattended autonomous administration.

### Security Limitation

Written instructions and approval requests are valuable workflow controls, but they do not independently enforce operating-system permissions.

Production-grade automation would require technical restrictions such as:

- Dedicated service identities
- Restricted management endpoints
- Scoped API credentials
- Command execution policies
- Auditable privileged operations
- Secret management
- Network-level segmentation

## 9. SIEM Access and Telemetry Validation

Once remote administration was available, Codex assisted with validating:

- Active Directory services
- DNS functionality
- Windows domain authentication
- Sysmon
- Windows Security auditing
- PowerShell Script Block Logging
- Elastic Agent
- Elasticsearch
- Kibana
- Fleet

An initial collection gap was identified on the Domain Controller.

The existing Windows 11 telemetry pipeline was operational, but the DC was not forwarding equivalent security events.

A dedicated Fleet policy and additional Windows auditing were configured.

After enrollment, the Domain Controller successfully transmitted security logs to Elasticsearch.

This enabled subsequent identity detection engineering.

## 10. Validated Outcome — Kerberos Detection

With Domain Controller telemetry operational, Codex assisted with creating an Elastic Security rule for repeated Kerberos preauthentication failures.

### Detection Parameters

| Parameter | Value |
|---|---|
| Windows event | 4771 |
| Failure status | `0x18` |
| Threshold | 3 failures |
| Time window | 5 minutes |
| Grouping | Account and source IP |
| Severity | Medium |
| Risk score | 47 |

A controlled test generated three authentication failures against a designated account.

The Domain Controller recorded the corresponding events.

Elastic Security subsequently generated the expected Medium-severity alert.

**Result:** Successful end-to-end detection validation.

The full detection investigation is documented separately:

[AI-Assisted Kerberos 4771 Detection Case Study](../detections/kerberos-4771-ai-assisted.md)

## 11. Security Risks and Improvements

The implementation successfully demonstrated AI-assisted remote administration, but it also identified areas requiring improvement.

| Area | Current Implementation | Planned Improvement |
|---|---|---|
| Linux access | Dedicated SSH key using existing account | Restricted automation identity |
| Windows access | WinRM with privileged domain credentials | Least-privilege remoting accounts |
| Credential storage | Windows-protected credential export | Dedicated secrets management |
| Network security | Lab-scoped inbound rules | Verify isolation and remove unnecessary network paths |
| Elastic administration | Authenticated Kibana / Fleet workflow | Scoped Elastic API roles |
| Change approval | Human approval in conversation | Enforced approval and change logging |
| Auditability | Conversation and troubleshooting history | Structured command and change logs |
| Recovery | Selected configuration backups | Tested rollback procedures |

## 12. Lessons Learned

### AI Access Is an Identity and Authorization Problem

Giving an AI assistant an administrative shell does not inherently provide safe automation.

The credentials, account permissions, network access, and supported commands determine the real security boundary.

### Credential Protection Is More Than Avoiding Plaintext

Using SSH keys or encrypted local credential files reduces certain exposure risks.

It does not eliminate the need for account restriction, credential rotation, audit logging, or trusted execution environments.

### Remote Access Must Be Scoped

A functioning WinRM service does not need to be accessible across every connected network.

Restricting inbound access to the intended lab interface reduces unnecessary exposure.

### Validate the Execution Context

A command executed in the wrong Windows session can produce misleading results or modify the wrong system.

Host identity and privilege context should be verified before administrative changes.

### Detection Automation Requires Telemetry Validation

The most important finding was a Domain Controller logging gap.

Fixing that gap made the Kerberos detection possible.

### AI Outputs Require Technical Verification

Codex assisted with diagnosing and configuring the environment, but the success of the work was established through system commands, event records, agent health, and an actual security alert.

## 13. Future Development

The next phase of this project will focus on engineering stronger technical safeguards around AI-assisted operations.

Planned work includes:

1. Creating dedicated least-privilege automation accounts.
2. Restricting PowerShell Remoting to approved administrative functions.
3. Reviewing SSH and sudo permissions.
4. Using scoped Elastic API keys for approved rule operations.
5. Implementing credential rotation and revocation procedures.
6. Producing sanitized execution and approval logs.
7. Exporting validated Elastic detection configurations.
8. Testing rollback and recovery procedures.
9. Evaluating reproducible automation scripts and rule deployment workflows.

These improvements are planned and should not be interpreted as already implemented.

---

## Conclusion

Integrating Codex into THE.WIRED transformed a primarily manual VMware laboratory into an environment capable of AI-assisted infrastructure diagnostics and detection engineering.

The work established authenticated access to Windows and Linux systems, verified Elastic SIEM functionality, closed a Domain Controller telemetry gap, and successfully validated a Kerberos 4771 detection.

The project also highlighted the security risks associated with privileged AI-assisted access.

The primary engineering lesson is that **effective AI automation requires both technical capability and deliberate control over identity, permissions, execution scope, and verification**.

---

**Project:** THE.WIRED Cybersecurity Homelab  
**Document:** AI-Assisted Infrastructure Access Architecture  
**Status:** Implemented and documented; security hardening ongoing
