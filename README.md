# SOC Investigation Report: KCD-Web Potential Malware / Ransomware Activity

**Case ID:** MYDFIR-2026-00644  
**Host:** `KCD-Web`  
**Investigation Date:** 2026-08-28  
**Primary User:** `KCD-Web\administrator`  
**Severity:** High  
**Status:** Investigated / Malicious activity confirmed

---

## Executive Summary

On August 28, 2026, suspicious activity was identified on `KCD-Web` involving an external Remote Desktop Protocol (RDP) connection, execution of `dControl.exe`, creation and execution of `screenconnect.exe` and `Stub.exe`, Microsoft Defender tampering, persistence, and recovery-inhibition activity.

At approximately **08:58:18**, the host received an inbound connection from `91.99.176.42` to TCP port `3389`. Windows subsequently recorded successful authentication for the `administrator` account, including a **Logon Type 10 (RemoteInteractive)** event at **08:58:26**, consistent with a successful RDP session.

Approximately one minute later, `dControl.exe` was created under:

```text
C:\Users\administrator\Pictures\dcontrol\dControl.exe
```

`dControl.exe` was executed and modified Microsoft Defender-related service and policy settings. Additional payloads were subsequently created, including `screenconnect.exe` and:

```text
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
```

`Stub.exe` then executed commands that deleted Volume Shadow Copies, modified Windows recovery settings, disabled Microsoft Defender protections, deleted Recycle Bin content, and established persistence through a per-user `Run` registry key. Shortly afterward, `Stub.exe` created:

```text
C:\PerfLogs\DataRecovery.txt
```

The filename, timing, and surrounding recovery-inhibition activity make this file consistent with a **suspected ransomware recovery/ransom note**, although its contents were not available in the reviewed telemetry.

The observed behavior is strongly consistent with **post-compromise ransomware preparation and defense evasion**. The investigation confirms malicious activity on `KCD-Web`, but the specific malware/ransomware family was not conclusively identified.

---

## Investigation Scope

The investigation focused on determining:

- How the suspicious activity began on `KCD-Web`
- Whether the host was accessed remotely
- How `dControl.exe` and related payloads were executed
- What defensive controls were modified
- Whether persistence was established
- Whether the activity included ransomware-like recovery inhibition
- Whether evidence of a ransom/recovery note was present

---

## Data Sources

The investigation primarily used:

- Windows Security Event Logs
- Sysmon telemetry
- Splunk
- Process creation events
- File creation events
- Registry modification events
- Network connection events

Important Sysmon Event IDs reviewed:

| Event ID | Description |
|---:|---|
| 1 | Process Create |
| 3 | Network Connection |
| 5 | Process Terminated |
| 7 | Image Loaded |
| 11 | File Create |
| 13 | Registry Value Set |

Important Windows Security Event IDs reviewed:

| Event ID | Description |
|---:|---|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4778 | RDP Session Reconnection |
| 4779 | RDP Session Disconnection |

---

# Investigation Timeline

## 1. Successful External RDP Access

At **08:58:18**, Sysmon Event ID 3 recorded a TCP connection from:

```text
Source IP:        91.99.176.42
Source Port:      58209
Destination IP:   172.16.1.7
Destination Port: 3389
Protocol:         TCP
```

A second connection to TCP/3389 occurred at **08:58:22**.

Windows Security Event ID 4624 then recorded successful authentication for the `administrator` account.

Observed authentication sequence:

```text
08:58:21  administrator  91.99.176.42  Logon Type 3
08:58:26  administrator  91.99.176.42  Logon Type 10
08:58:26  administrator  91.99.176.42  Logon Type 10
```

### Interpretation

- **Logon Type 3** represents a network logon.
- **Logon Type 10** represents a RemoteInteractive logon, commonly associated with RDP.

The Type 3 event did not "turn into" Type 10. Instead, these events represent different stages of authentication and remote session establishment.

No failed logon attempts from `91.99.176.42` were identified immediately before the successful session. Based on the available telemetry, this does **not** appear to be a brute-force login against `KCD-Web`.

The evidence is more consistent with the remote user already possessing valid `administrator` credentials.

### Splunk Query

```spl
index=* host=KCD-Web
earliest="8/28/2026:08:00:00"
latest="8/28/2026:09:00:00"
src_ip=91.99.176.42
| sort + _time
| table _time host EventCode user src_ip dest_ip dest_port Logon_Type
```

---

## 2. `dControl.exe` Created

At approximately **08:59:40**, `dControl.exe` was created on `KCD-Web` under the administrator profile:

```text
C:\Users\administrator\Pictures\dcontrol\dControl.exe
```

### Splunk Query

```spl
index=* host="KCD-Web"
earliest="8/28/2026:08:00:00"
dControl.exe EventCode=11
| table UtcTime host User TargetFilename action process_path process_guid
| sort + UtcTime
```

The timing is significant because the file appeared roughly one minute after the successful RDP logon.

---

## 3. `dControl.exe` Executed

At approximately **09:00:04**, `dControl.exe` was executed.

Observed parent process:

```text
C:\Windows\Explorer.EXE
```

The `explorer.exe` parent is consistent with execution occurring from an interactive Windows user session.

It does **not**, by itself, prove that the user manually double-clicked the executable.

---

## 4. Microsoft Defender Tampering

Beginning at approximately **09:00:11**, `dControl.exe` modified Microsoft Defender-related registry values.

Observed targets included:

```text
HKLM\System\CurrentControlSet\Services\WdFilter\Start
HKLM\System\CurrentControlSet\Services\WdNisSvc\Start
HKLM\System\CurrentControlSet\Services\WinDefend\Start
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
```

The modifications were consistent with attempts to weaken or disable Microsoft Defender protections.

Additional temporary files were created or modified under:

```text
C:\Windows\Temp\
```

At approximately **09:00:11**, `dControl.exe` also created:

```text
C:\Windows\System32\GroupPolicy\Machine\Registry.pol
```

`Registry.pol` is a legitimate Windows Group Policy file, but creation or modification by a suspicious executable during Defender tampering is noteworthy.

At approximately **09:00:13**, `dControl.exe` terminated.

---

## 5. Additional Payloads Created

Telemetry associated with the same activity showed creation/execution of:

```text
C:\Users\administrator\Pictures\dcontrol\screenconnect.exe
```

and creation of:

```text
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
```

The presence of a file named `screenconnect.exe` should not automatically be interpreted as legitimate ConnectWise ScreenConnect software. In this investigation, the surrounding behavior was suspicious.

---

## 6. `Stub.exe` Execution

At approximately **09:00:55**, `Stub.exe` executed and launched multiple commands associated with system recovery inhibition and defense evasion.

Observed path:

```text
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
```

---

## 7. Volume Shadow Copy Deletion

`Stub.exe` launched commands including:

```cmd
vssadmin Delete Shadows /All /Quiet
```

This command deletes all Windows Volume Shadow Copies without prompting the user.

Volume Shadow Copies are frequently used for backup and recovery. Their deletion is a common ransomware technique intended to make local file recovery more difficult.

Additional shadow-copy related activity included:

```cmd
wmic SHADOWCOPY /nointeractive
```

---

## 8. Windows Recovery Configuration Modified

`Stub.exe` also executed:

```cmd
bcdedit /set {default} bootstatuspolicy ignoreallfailures
```

and:

```cmd
bcdedit /set {default} recoveryenabled No
```

These commands alter Windows Boot Configuration Data and reduce the system's ability to automatically enter recovery after boot failure.

Combined with shadow-copy deletion, this behavior is consistent with attempts to **inhibit system recovery**.

---

## 9. Microsoft Defender Protections Disabled

Registry activity associated with `Stub.exe` modified Microsoft Defender Real-Time Protection settings, including:

```text
DisableIOAVProtection
DisableOnAccessProtection
DisableScanOnRealtimeEnable
DisableBehaviorMonitoring
DisableRealtimeMonitoring
```

These modifications are consistent with attempts to impair security controls before or during malicious activity.

---

## 10. Recycle Bin Content Deleted

`Stub.exe` also launched commands targeting Recycle Bin directories across multiple drive letters.

Observed behavior included use of:

```cmd
rd /s /q
```

against locations such as:

```text
$RECYCLE.BIN
Recycler
```

This behavior is consistent with destructive cleanup or attempts to reduce file recovery options.

---

## 11. Persistence Established

At approximately **09:00:57**, `Stub.exe` established per-user persistence by modifying:

```text
HKU\S-1-5-21-3772984715-3855048566-1297946058-1001\
Software\Microsoft\Windows\CurrentVersion\Run\61E52490E32E7D80
```

The registry value data pointed back to:

```text
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
```

This would cause the executable to be launched during future user logon processing.

---

## 12. Suspected Ransomware Note Created

At approximately **09:01:00**, Sysmon Event ID 11 recorded `Stub.exe` creating:

```text
C:\PerfLogs\DataRecovery.txt
```

The event directly associated the file creation with:

```text
Image:
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
```

### Interpretation

`C:\PerfLogs` is a legitimate Windows directory normally used for performance logging. The creation of a file named `DataRecovery.txt` in this directory immediately after shadow-copy deletion, recovery modification, Defender tampering, and persistence activity is suspicious.

The file is assessed as a **suspected ransomware recovery/ransom note**.

However, the contents of the file were not available in the reviewed telemetry. Therefore, it should not be described as a confirmed ransom note without additional evidence.

---

# Process / Attack Flow

```text
91.99.176.42
      |
      | TCP/3389
      v
KCD-Web (172.16.1.7)
      |
      |-- 08:58:21  Successful network logon - administrator
      |
      |-- 08:58:26  Successful RDP Logon Type 10
      |
      v
Interactive Windows Session
      |
      v
explorer.exe
      |
      +--> dControl.exe
      |      |
      |      +--> Defender registry/service modifications
      |      +--> Temporary file creation
      |      +--> Registry.pol creation
      |
      +--> screenconnect.exe
      |
      +--> Stub.exe
             |
             +--> Delete Volume Shadow Copies
             +--> Modify BCD / disable recovery
             +--> Disable Defender protections
             +--> Delete Recycle Bin content
             +--> Create Run-key persistence
             |
             +--> C:\PerfLogs\DataRecovery.txt
```

---

# Indicators of Compromise

## Network

| Indicator | Type | Context |
|---|---|---|
| `91.99.176.42` | IPv4 | Source of successful RDP connection |
| `172.16.1.7:3389` | Host/Port | RDP destination on KCD-Web |

## Files

```text
C:\Users\administrator\Pictures\dcontrol\dControl.exe
C:\Users\administrator\Pictures\dcontrol\screenconnect.exe
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
C:\PerfLogs\DataRecovery.txt
C:\Windows\System32\GroupPolicy\Machine\Registry.pol
```

## Registry

```text
HKLM\System\CurrentControlSet\Services\WdFilter\Start
HKLM\System\CurrentControlSet\Services\WdNisSvc\Start
HKLM\System\CurrentControlSet\Services\WinDefend\Start

HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware

HKU\S-1-5-21-3772984715-3855048566-1297946058-1001\
Software\Microsoft\Windows\CurrentVersion\Run\61E52490E32E7D80
```

---

# MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Remote Services: Remote Desktop Protocol | T1021.001 | Successful external RDP session to KCD-Web |
| Impair Defenses | T1562.001 | Microsoft Defender protections modified/disabled |
| Modify Registry | T1112 | Multiple Defender and persistence registry modifications |
| Registry Run Keys / Startup Folder | T1547.001 | `Stub.exe` added to CurrentVersion\\Run |
| Inhibit System Recovery | T1490 | Shadow copies deleted and Windows recovery disabled |
| Windows Management Instrumentation | T1047 | `wmic SHADOWCOPY` activity |
| Remote Access Software | T1219 | Suspicious `screenconnect.exe` execution, pending binary validation |

> Note: MITRE mappings describe observed behavior and do not identify a specific malware family.

---

# Key Findings

1. An external system at `91.99.176.42` successfully established an RDP session to `KCD-Web` using the `administrator` account.
2. No failed logon attempts from that source were identified immediately before the successful session.
3. `dControl.exe` appeared and executed shortly after the RDP session was established.
4. `dControl.exe` modified Microsoft Defender service and policy configuration.
5. Additional suspicious executables, including `screenconnect.exe` and `Stub.exe`, were created/executed.
6. `Stub.exe` deleted Volume Shadow Copies and altered Windows recovery configuration.
7. `Stub.exe` disabled multiple Defender Real-Time Protection settings.
8. `Stub.exe` established persistence through a per-user Run key.
9. `Stub.exe` created `C:\PerfLogs\DataRecovery.txt`, assessed as a suspected ransomware recovery/ransom note.
10. The combined activity is strongly consistent with ransomware preparation and defense evasion, although the specific malware family was not conclusively identified.

---

# Analyst Assessment

**Disposition:** True Positive / Malicious

The evidence supports successful unauthorized remote access followed by execution of malicious tooling, security-control impairment, persistence, and recovery-inhibition activity.

The sequence of RDP access, Defender tampering, shadow-copy deletion, BCD modification, persistence, and creation of `DataRecovery.txt` strongly supports a ransomware-related intrusion scenario.

The investigation did **not** establish:

- How the `administrator` credentials were originally obtained
- Whether the RDP source IP represents the original attacker system or an intermediary host
- The exact transfer method used to place `dControl.exe` on the endpoint
- Whether files were successfully encrypted
- The specific ransomware family
- The contents of `DataRecovery.txt`

These remain areas for additional investigation.

---

# Recommended Response Actions

## Containment

- Isolate `KCD-Web` from the network.
- Block `91.99.176.42` at applicable network security controls.
- Disable or reset the compromised `administrator` account.
- Invalidate active sessions and credentials associated with the account.
- Restrict or disable externally exposed RDP where not operationally required.

## Eradication

- Remove or quarantine:
  - `dControl.exe`
  - `screenconnect.exe`
  - `Stub.exe`
- Remove malicious Run-key persistence.
- Restore Microsoft Defender service and policy configuration.
- Review `Registry.pol` for unauthorized policy modifications.
- Search other endpoints for matching filenames, hashes, registry values, and source IP activity.

## Recovery

- Validate Windows Defender configuration.
- Restore recovery settings modified by `bcdedit`.
- Validate backup integrity before restoration.
- Rebuild the endpoint if trust in the operating system cannot be re-established.
- Continue monitoring the compromised account and host for recurring activity.

---

# Additional Hunting Queries

## Search the RDP Source IP Across All Hosts

```spl
index=* src_ip="91.99.176.42"
| sort + _time
| table _time host EventCode user src_ip dest_ip dest_port Logon_Type action
```

## Search for `dControl.exe`

```spl
index=* "dControl.exe"
| sort + _time
| table _time host EventCode User ParentImage process_name process_path CommandLine TargetFilename Hashes
```

## Search for `Stub.exe`

```spl
index=* "Stub.exe"
| sort + _time
| table _time host EventCode User ParentImage process_name process_path CommandLine TargetFilename registry_path Hashes
```

## Search for Recovery-Inhibition Commands

```spl
index=*
("vssadmin" OR "wmic SHADOWCOPY" OR "recoveryenabled No" OR "ignoreallfailures")
| sort + _time
| table _time host User ParentImage process_name process_path CommandLine
```

## Search for Defender Tampering

```spl
index=*
("DisableRealtimeMonitoring"
 OR "DisableBehaviorMonitoring"
 OR "DisableAntiSpyware"
 OR "DisableAntiVirus"
 OR "WdFilter"
 OR "WdNisSvc"
 OR "WinDefend")
| sort + _time
| table _time host EventCode User process_name process_path registry_path registry_value_name registry_value_data
```

## Search for the Persistence Value

```spl
index=* "61E52490E32E7D80"
| sort + _time
| table _time host EventCode User process_name process_path registry_path registry_value_data
```

---

# Conclusion

The investigation identified a successful external RDP session to `KCD-Web` followed by execution of suspicious tooling and multiple behaviors commonly associated with ransomware operations.

The strongest indicators were:

- Successful RDP access from `91.99.176.42`
- `dControl.exe` execution
- Microsoft Defender tampering
- Creation/execution of `screenconnect.exe` and `Stub.exe`
- Volume Shadow Copy deletion
- Windows recovery modification
- Run-key persistence
- Creation of `C:\PerfLogs\DataRecovery.txt`

While the specific ransomware family remains unknown, the combined telemetry is sufficient to classify the observed activity as malicious and ransomware-related.

---

## Investigation Notes

This report intentionally distinguishes between **confirmed telemetry** and **analyst assessment**. Where the available logs do not prove a specific action—such as how credentials were obtained, whether a user manually double-clicked a file, or whether `DataRecovery.txt` contained ransom instructions—the report uses qualified language rather than presenting assumptions as fact.
