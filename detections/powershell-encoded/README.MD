# Suspicious PowerShell Encoded Command

## Mô tả
Phát hiện việc sử dụng PowerShell với tham số `-enc` (encoded command), một kỹ thuật thường được attacker sử dụng để obfuscate payload và né tránh detection.

Đây là hành vi phổ biến trong các giai đoạn execution.

---

## MITRE ATT&CK
- Technique: T1059.001 – Command and Scripting Interpreter: PowerShell 
- Tactic: Execution

---

## Nguồn log
- Sysmon Event ID: 1 (Process Create)
- Field quan trọng:
  - Image
  - CommandLine
  - ParentImage
  - User

---

## Mô phỏng tấn công

### Manual
```powershell
$cmd = "calc.exe"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)

powershell -enc $encoded
```

### Atomic Red Team
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

## Logic phát hiện
- Xác định process PowerShell
- Kiểm tra command-line có chứa `-enc`
- Đây là dấu hiệu của việc thực thi mã đã được encode

## SPL Detection
```spl
index=labsoc Channel="Microsoft-Windows-Sysmon/Operational"
Category="Process Create (rule: ProcessCreate)"
CommandLine="*powershell*"
| where match(CommandLine, "(?i)-enc")
| stats count by host, User, CommandLine, ParentImage
```

## Kết quả mong đợi
- Alert được trigger khi chạy PowerShell encoded
- Hiển thị: Host, User, CommandLine, Parent process

## Phân tích
### Vì sao rule này hoạt động
Tham số `-enc` rất hiếm khi xuất hiện trong hoạt động hợp lệ thông thường, nhưng lại phổ biến trong các kỹ thuật tấn công.

### Điểm mạnh
- Dễ triển khai
- Phát hiện được hành vi obfuscation

### False Positive
- Script automation nội bộ
- Admin sử dụng PowerShell encoded

### Hạn chế
Attacker có thể:
- Không dùng `-enc`
- Dùng `-EncodedCommand`
- Encode theo cách khác

## Cải tiến
- Detect pattern base64 thay vì chỉ `-enc`
- Correlate với parent process (Word, Excel)
- Kết hợp frequency (user hiếm khi dùng → alert mạnh hơn)
