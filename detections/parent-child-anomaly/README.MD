# Suspicious Parent-Child Process Relationship

## Mô tả
Phát hiện mối quan hệ bất thường giữa process cha và process con, đặc biệt khi các ứng dụng như Office hoặc Explorer spawn các process dòng lệnh như `cmd.exe` hoặc `powershell.exe`.

Đây là dấu hiệu phổ biến của:
- Macro-based attack
- User execution bị lợi dụng
- Initial access / execution

---

## MITRE ATT&CK
- Technique: T1059.001 – Command and Scripting Interpreter: PowerShell 
- Technique: T1204.002 – User Execution: Malicious File 
- Tactic: Execution

---

## Nguồn log
- Sysmon Event ID: 1 (Process Create)

### Field quan trọng:
- Image (process con)
- ParentImage (process cha)
- CommandLine
- User

---

## Mô phỏng tấn công

### Manual
```cmd
start powershell.exe
```
Hoặc:
```cmd
Win + R → nhập cmd
```

## Logic phát hiện
- Xác định các process nguy hiểm: `cmd.exe`, `powershell.exe`
- Kiểm tra parent process bất thường: `winword.exe`, `excel.exe`, `outlook.exe`, `explorer.exe`
- Loại bỏ command hợp lệ (nếu có)

## SPL Detection
```spl
index=labsoc earliest=-5m
Category="Process Create (rule: ProcessCreate)"
| where match(Image, "(?i)powershell.exe|cmd.exe")
| where match(ParentImage, "(?i)winword.exe|excel.exe|outlook.exe|explorer.exe|powershell.exe")
| where NOT match(CommandLine, "(?i)legit_script") 
| stats count by host, user, ParentImage, Image, CommandLine
```

## Kết quả mong đợi
Alert khi process dòng lệnh được spawn từ parent bất thường
Hiển thị:
- Parent process
- Child process
- CommandLine
- User

## Phân tích
### Vì sao rule này hoạt động
Trong môi trường bình thường:
- Word / Excel không nên spawn cmd hoặc PowerShell
- Explorer có thể spawn, nhưng cần theo context

→ Khi xuất hiện mối quan hệ này → khả năng cao là hành vi đáng nghi.

### Điểm mạnh
- Detect hành vi (behavior-based) → không phụ thuộc signature
- Bắt được nhiều attack chain:
  - Macro → PowerShell
  - User click → cmd execution

### False Positive
- Người dùng mở cmd từ Run (Win + R)
- Script nội bộ
- Admin thao tác

### Hạn chế
- Explorer.exe spawn cmd là hợp lệ trong nhiều trường hợp
- Không có context: File nào spawn? User intent là gì?

## Cải tiến
- Tăng độ chính xác: Loại bỏ explorer.exe hoặc xử lý riêng
- Focus mạnh vào: `winword.exe`, `excel.exe`
