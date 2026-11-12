


# Digital Forensics & Incident Response (DFIR): Compromised Host Analysis

## Executive Summary
This case study documents a targeted digital forensics investigation conducted on a compromised Windows Server environment within the TryHackMe ecosystem. The objective was to perform a thorough post-breach analysis to identify active persistence mechanisms, discover unauthorized privilege escalation vectors, locate malicious artifacts, and identify attacker network infrastructure.

## Investigation Objectives
* **Privilege Auditing:** Identify unauthorized local user accounts possessing administrative rights.
* **Persistence Mechanism Detection:** Track down rogue system configurations used by the threat actor to maintain access.
* **Malicious Artifact Analysis:** Locate and inspect the specific files or scripts executed by unauthorized system tasks.
* **Network Infrastructure Scoping:** Determine the local communication channels and ports targeted by the attacker's backdoors.

---

## Step-by-Step Investigation & Findings

### 1. Privilege Escalation & Unauthorized Account Auditing
The first step of the investigation involved auditing user group membership to verify who holds administrative control over the machine. 

Using PowerShell, the system's local administrators group configuration was checked to verify accounts beyond the default `Administrator` profile:

```powershell
Get-LocalGroupMember -Group "Administrators"
```

#### Findings:
The query revealed that two unauthorized accounts had been granted full administrative privileges, exposing a severe compromise of system access control:
* **Jenny**
* **Guest** (An elevated default account that should strictly remain disabled/unprivileged)

![Administrative Accounts Audit](screenshots/Admin_group.jpg
)

---

### 2. Identifying Attacker Persistence Mechanisms
To ensure their access survived system restarts, the attacker established a persistent backdoor configuration. The system's automated operational triggers were audited using the **Windows Task Scheduler Utility**.

#### Findings:
A highly suspicious, non-standard scheduled background maintenance task was discovered under the name:
* **`Clean file system`**

While named to look like an innocent background maintenance script, it was flag-marked to run automatically every single day without user interaction.

![Scheduled Task Discovery](screenshots/Scheduled_tasks.png)

---

### 3. Artifact & Technical Malicious Code Extraction
By drilling deeper into the properties of the discovered task and checking its designated runtime actions, the underlying malicious script was exposed.

#### Findings:
The task properties confirmed that it was built explicitly to execute an external standalone script file located deep within a temporary directory path:
* **`C:\TMP\nc.ps1`**

[Malicious Script Analysis](screenshots/Malicious_script.jpg) 

---

### 4. Code Scoping & Network Infrastructure Mapping
The final step involved performing basic static analysis on the task properties to determine what network parameters the automated backdoor was targeting upon execution.

#### Findings:
Inspecting the execution arguments directly within the Task Scheduler Actions pane revealed that the `nc.ps1` script (a PowerShell-based Netcat utility variant) was passing explicit instructions to listen silently for incoming connections:
* **Runtime Command:** `C:\TMP\nc.ps1 -l 1348`
* **Target Listening Port:** **`1348`** (The `-l` argument flags a persistent listener, effectively serving as an active entry point waiting for a command-and-control connection).

![Network Port Configuration](screenshots/Malicious_script.png)

---

## Indicators of Compromise (IoCs) Summary

| IoC Type | Artifact / Value | Operational Context / Notes |
| :--- | :--- | :--- |
| **Unauthorized Admin User** | `Jenny` | Rogue local account created by threat actor |
| **Unauthorized Admin User** | `Guest` | Default account maliciously added to local Admin group |
| **Persistence Mechanism** | `Clean file system` | Rogue Scheduled Task configured for daily execution |
| **Malicious File Path** | `C:\TMP\nc.ps1` | PowerShell implementation of Netcat network utility |
| **Network Vector** | Port `1348` | Active inbound listener established for backdoor access |

---

## Conclusion & Remediation Guidance
Based on the evidence network uncovered during this DFIR investigation, the following immediate remediation steps are recommended:
1. **Revoke Privileges:** Immediately remove the `Jenny` and `Guest` accounts from the Local Administrators group and disable the profiles.
2. **Eliminate Persistence:** Terminate and delete the rogue `Clean file system` scheduled task from the system configuration.
3. **Purge Artifacts:** Securely delete the malicious directory structure and script files located at `C:\TMP\nc.ps1`.
4. **Network Hardening:** Implement firewall blocking rules to drop traffic targeting port `1348` and run network sweeps to look for active outgoing beacons.
