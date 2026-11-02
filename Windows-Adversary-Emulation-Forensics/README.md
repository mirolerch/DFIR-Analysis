# Case 01 – Windows Endpoint Compromise Investigation

**Host:** DESKTOP-R39QKFP (Windows 10 Pro x64, build 19041) · **User:** lweber  
**Analyst:** Miroslaw Lerch · **Type:** Lab investigation (simulated adversary activity)  
**All times in UTC.** Local time of the host during the incident: UTC+2.

---

## Executive Summary

On 2026-10-19 an alert reported suspicious PowerShell activity and a new local administrator account on DESKTOP-R39QKFP. Memory and disk were acquired and analysed.

The alert is a **true positive**. Within about 45 seconds (19:09:38 – 19:10:24) a PowerShell script started from the user's Downloads folder:

- downloaded a macro-enabled Office document from the internet,
- created the local administrator account **art-test**,
- ran a Base64 payload stored in the registry,
- installed **five persistence mechanisms** (Run key, two Startup folder scripts, two scheduled tasks, one service),
- injected a DLL into **notepad.exe**.

The service process and the injected notepad.exe were still running when memory was captured (19:22:19). The art-test account was never used to log on. No deletion of evidence was found.

**Impact:** The attacker had administrator rights and several ways to regain access after a reboot. The host must be treated as compromised and rebuilt.

---

## 1. Scenario

### Alert

| Field | Value |
|---|---|
| Alert | Suspicious PowerShell execution – new local admin account created |
| Severity | High |
| Host / User | DESKTOP-R39QKFP / lweber |
| Time | 2026-10-19 ~19:09 UTC |
| Status | Host isolated, memory and disk acquired |

### Scope and Objectives

The investigation answers these questions, using only evidence from the acquired images:

1. Was the alert a true positive?
2. What was executed, when and by whom?
3. Which persistence mechanisms were installed?
4. Was evidence deleted or hidden?
5. What must be done to clean the host and detect this activity in the future?

Out of scope: network traffic analysis, malware reverse engineering, other hosts.

### Intended Audience

- **Management:** Executive Summary and IR Actions
- **SOC / IR team:** Findings, Timeline, IOCs, Detection Opportunities

### Lab Environment

- VirtualBox VM, Windows 10 Pro, local admin user `lweber`
- Sysmon (SwiftOnSecurity config), PowerShell logging, process creation auditing
- Adversary activity simulated with Atomic Red Team

---

## 2. Tools Used

| Phase | Tools |
|---|---|
| Acquisition | VBoxManage (`dumpvmcore`, `clonemedium`), Get-FileHash |
| Preparation | Arsenal Image Mounter (write-temporary mode), KAPE (KapeTriage) |
| Registry | Registry Explorer, RegRipper, AppCompatCacheParser, AmcacheParser |
| File system | MFTECmd ($MFT, $UsnJrnl:$J), Timeline Explorer |
| Execution | PECmd (Prefetch) |
| Persistence | Registry Explorer, Sysinternals Autoruns (offline mode) |
| Event logs | EvtxECmd, Event Log Explorer, CyberChef (Base64 decode) |
| Memory | Volatility 3 (2.28.0), strings |

---

## 3. Findings

##
