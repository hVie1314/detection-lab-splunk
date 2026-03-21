# Alerts Overview

Tài liệu này mô tả tất cả các cảnh báo được triển khai trong  Detection Lab.

---

## 1. PowerShell Encoded Command

- **Name:** SOC - Suspicious PowerShell Encoded Command  
- **Severity:** High  
- **MITRE:** T1059.001 – Command and Scripting Interpreter: PowerShell 

**Description:**  
Detects PowerShell execution with encoded command, which may indicate obfuscation or malicious activity.

---

## 2. LSASS Credential Dumping

- **Name:** SOC - Suspicious LSASS Access (High Privilege)  
- **Severity:** Critical  
- **MITRE:** T1003.001 – OS Credential Dumping: LSASS Memory

**Description:**  
Detects high-privilege access to LSASS memory (0x1fffff), commonly associated with credential dumping tools such as Mimikatz or ProcDump.

---

## 3. Registry Run Key Persistence

- **Name:** SOC - Suspicious Registry Run Key Persistence  
- **Severity:** Medium  
- **MITRE:** T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**Description:**  
Detects modifications to registry Run keys used for persistence.

---

## 4. Parent-Child Process Anomaly

- **Name:** SOC - Suspicious Process Spawn from Explorer  
- **Severity:** High  
- **MITRE:** T1204.002 – User Execution: Malicious File  

**Description:**  
Detects suspicious command-line processes spawned from user-facing applications such as explorer.exe.

