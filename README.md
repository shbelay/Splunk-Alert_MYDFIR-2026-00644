# KCD-Web Potential Malware

**Case ID:** MYDFIR-2026-00644  
**Host:** KCD-Web  
**Alert Raised Date:** 2026-08-28 09:00 UTC  
**Primary User:** KCD-Web\administrator with SYSTEM privileges

---

## 1. Event Codes and Field Types


### Splunk Query

```spl
index=* host="KCD-Web" dControl.exe | sort + _time
```

```spl
index=* host="KCD-Web" dControl.exe | dedup EventCode | table EventCode EventDescription
```

<img width="459" height="351" alt="image" src="https://github.com/user-attachments/assets/2ea6dae2-d123-4adf-b80b-db173c096b12" />

---

## 2. Event 11 - File Create

```spl
index=* host="KCD-Web" earliest="8/28/2026:08:00:00" dControl.exe EventCode=11
| table UtcTime host User TargetFilename action process_path process_guid
| sort + UtcTime
```

Process GUIDs

```text
{587438d6-4db8-6a91-dc20-000000000a00}
```
```text
{587438d6-4e18-6a91-2e21-000000000a00}
```
```text
{587438d6-4e18-6a91-3021-000000000a00}
```
---

## 4. Process GUID 2021

```spl
index=* {587438d6-4db8-6a91-dc20-000000000a00}
| table _time EventCode EventDescription ParentImage process_path TargetFilename action
| sort + _time
```

Telemetry showed creation/execution of:

```text
C:\Users\administrator\Pictures\dcontrol\screenconnect.exe
```

and creation of:

```text
C:\Users\administrator\Pictures\dcontrol\x64-Release\Stub.exe
```

---

## 4. Process GUID 3021

```spl
index=* {587438d6-4e18-6a91-3021-000000000a00}
| table UtcTime EventCode EventDescription User process_path process_name CommandLine TargetFilename registry_path registry_value_name registry_value_data action
| sort + UtcTime
```

---

## 6. Stub.exe

```spl
index=* host="KCD-Web" "Stub.exe" earliest="8/28/2026:09:00:30" latest="8/28/2026:09:10:00"
(EventCode=1 OR EventCode=5 OR EventCode=11 OR EventCode=13)
| table _time EventCode EventDescription User ParentImage process_name process_path CommandLine TargetFilename registry_path registry_value_name registry_value_data action
| sort + _time
```

---

## 7. Investigated after DataRecovery.txt but no logs

Checked to see if ransom notes were left anywhere else in the environment
```spl
index=* "DataRecovery.txt"
```

Checked for file creation that mimics ransomware with unique file extensions or file deletions
```spl
index=* earliest="8/28/2026:08:30:00" latest="8/28/2026:10:30:00" (EventCode=11 OR EventCode=23) | table _time host Image file_path | sort _time
```

Queried Stub.exe across the environment with hash and name
```spl
index=* "Stub.exe" | table _time Image Hashes
```

Queried those values across the environment
```spl
index=* ("2D5E72B81C236DB1FD30978E2AD6A20D241945090B90F2CC2A36993469DC144F" OR "B0A2B3C075C7E705DC31E872F51FDFF00F571B8B806D025FE4867B340A7EF08C" OR "Stub.exe")
```

Queried outbound activity with the IP address found later 
```spl
index=* 91.99.176.42 | sort + _time | table _time EventCode EventDescription process_name process_path QueryName user action
```

Looked for network activity
```spl
index=* earliest="8/28/2026:08:30:00" latest="8/28/2026:10:30:00" EventCode=3
| stats count values(process_name) AS processes
        values(process_path) AS process_paths
        values(dest_port) AS destination_ports
        values(User) AS users
        by dest_ip
| sort - count
```

DNS Queries
```spl
index=* earliest="8/28/2026:08:30:00" latest="8/28/2026:10:30:00" EventCode=22
| stats count
        values(User) AS users
        values(process_name) AS processes
        values(process_path) AS process_paths
        values(process_guid) AS process_guids
        by QueryName
| sort – count
```

File compression / archiving evidence
```spl
index=* earliest="8/28/2026:09:00:00" latest="8/28/2026:11:00:00" EventCode=1 (CommandLine="*7z*" OR CommandLine="*rar*" OR CommandLine="*tar*" OR CommandLine="*rclone*" OR CommandLine="*curl*" OR CommandLine="*scp*") | table _time User ParentImage process_name process_path CommandLine | sort + _time
```

---

## 8. Initial Access

```spl
index=* host="KCD-Web" earliest="8/28/2026:08:45:00" latest="8/28/2026:09:00:00" (EventCode=4624 OR EventCode=4625) | table _time EventCode src_ip | sort + _time
```

```spl
index=* host=KCD-Web src_ip=91.99.176.42 | table _time host EventCode user src_ip dest_ip dest_port Logon_Type | sort + _time 
```

---

# Conclusion

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
