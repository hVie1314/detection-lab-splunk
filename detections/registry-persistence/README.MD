# Registry Persistence

# Suspicious Registry Run Key Persistence

## Mô tả
Phát hiện thay đổi registry Run key – kỹ thuật persistence phổ biến giúp attacker tự động chạy khi user đăng nhập.

---

## MITRE ATT&CK
- Technique: T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- Tactic: Persistence

---

## Nguồn log
- Sysmon Event ID: 13 (Registry Set)
- Field:
  - TargetObject
  - Details
  - Image
  - User

---

## Mô phỏng tấn công

### Manual
```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /t REG_SZ /d "calc.exe" /f
```

### Atomic Red Team
```powershell
Invoke-AtomicTest T1547.001 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

## Logic phát hiện
- Monitor thay đổi tại Run key
- Phát hiện entry mới được thêm
- Loại bỏ ứng dụng phổ biến

## SPL Detection
```spl
index=labsoc earliest=-5m
Category="Registry value set (rule: RegistryEvent)"
| where like(TargetObject, "%\\CurrentVersion\\Run\\%")
| where NOT match(Image, "(?i)OneDrive.exe|Teams.exe|svchost.exe")
| stats count by host, user, TargetObject, Details, Image
```

## Kết quả mong đợi
- Alert khi có key mới trong Run
- Hiển thị: Registry path, Giá trị, Process tạo

## Phân tích
### Vì sao rule này hoạt động
Run key là kỹ thuật persistence cực kỳ phổ biến và dễ triển khai.

### Điểm mạnh
- Visibility tốt
- Dễ validate

### False Positive
- Cài đặt phần mềm
- Update ứng dụng

### Hạn chế
Attacker có thể:
- Dùng key khác
- Sửa key sẵn có
- Dùng scheduled task thay thế

## Cải tiến
- Baseline registry trước đó
- Alert khi có entry lạ 
- Correlate với process bất thường
