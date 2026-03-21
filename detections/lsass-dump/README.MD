# LSASS Dump Detection

# Suspicious LSASS Memory Access

## Mô tả
Phát hiện hành vi truy cập vào tiến trình `lsass.exe` với quyền cao, dấu hiệu mạnh của credential dumping.

Các tool như Mimikatz, ProcDump thường sử dụng kỹ thuật này.

---

## MITRE ATT&CK
- Technique: T1003.001 – OS Credential Dumping: LSASS Memory
- Tactic: Credential Access

---

## Nguồn log
- Sysmon Event ID: 10 (Process Access)
- Field:
  - SourceImage
  - TargetImage
  - GrantedAccess
  - User

---

## Mô phỏng tấn công

### Manual
```bash
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### Atomic Red Team
```powershell
Invoke-AtomicTest T1003.001 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

## Cấu hình Sysmon
```xml
<ProcessAccess onmatch="include">
    <TargetImage condition="contains">lsass.exe</TargetImage>
</ProcessAccess>
```

## Logic phát hiện
- Theo dõi process truy cập lsass.exe
- Kiểm tra quyền truy cập cao (0x1fffff)
- Loại bỏ process hợp lệ

## SPL Detection
```spl
index=labsoc
TargetImage="*lsass.exe"
| where NOT match(SourceImage, "(?i)lsass.exe|vmtoolsd.exe|wmiprvse.exe|MicrosoftEdgeUpdate.exe")
| where match(GrantedAccess, "(?i)1fffff")
| stats count by host, user, SourceImage, TargetImage, GrantedAccess
| eval severity="critical", technique="T1003", tactic="Credential Access"
```

## Kết quả mong đợi
- Alert khi có process truy cập LSASS với quyền cao
- Hiển thị process nguồn và quyền truy cập

## Phân tích
### Vì sao rule này hoạt động
LSASS chứa credential của hệ thống → bất kỳ truy cập bất thường nào đều có giá trị detection cao.

### Điểm mạnh
- High fidelity (độ chính xác cao)
- Rất ít false positive nếu filter tốt

### False Positive
- EDR / antivirus
- Tool quản trị hệ thống

### Hạn chế
Attacker có thể:
- Inject vào process hợp lệ
- Dump bằng kỹ thuật khác
- Bypass Sysmon logging

## Cải tiến
- Xây dựng whitelist rõ ràng
- Correlate với process creation
- Detect chain: dump → file write
