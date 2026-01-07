# EASM_Scan V2 掃描工具使用說明

## 功能概述

Easmscan.py 是簡易的外部攻擊面管理 (EASM) 掃描工具，採用兩階段掃描策略與多執行緒技術，能夠高效掃描大量 IP 目標並產出較為專業的 Excel 報告。

## 核心特性

- ✅ **兩階段掃描**：先快速掃描全 Port，再針對開啟的 Port 進行深度掃描
- ✅ **多執行緒處理**：使用 ThreadPoolExecutor 提升掃描效率
- ✅ **歷史比對**：自動比對 scan_history.json，標註變動狀態
- ✅ **Excel 多工作表報告**：包含 5 個專業工作表，針對不同受眾
- ✅ **美化樣式**：標題列自動加粗、底色填滿、欄寬自動調整

## 系統需求

### 作業系統
- Linux (推薦 Ubuntu/Debian)
- macOS
- Windows (需安裝 Nmap)

### Python 版本
- Python 3.6 或更高版本

## 安裝步驟

### 1. 安裝系統套件

#### Ubuntu/Debian Linux
```bash
sudo apt-get update
sudo apt-get install -y nmap python3-pip
```

#### macOS
```bash
brew install nmap
```

#### Windows
1. 下載並安裝 Nmap: https://nmap.org/download.html
2. 確保 Nmap 已加入系統 PATH

### 2. 安裝 Python 套件

```bash
# 使用 pip3 安裝必要套件
pip3 install python-nmap openpyxl requests

# 或使用 sudo（如果需要系統級安裝）
sudo pip3 install python-nmap openpyxl requests
```

### 3. 驗證安裝

```bash
# 檢查 Nmap 是否安裝成功
nmap --version

# 檢查 Python 套件
python3 -c "import nmap; import openpyxl; import requests; print('所有套件安裝成功')"
```

## 使用方法

### 基本用法

```bash
# 使用 sudo 執行（推薦，避免深度掃描權限問題）
sudo python3 Easmscan.py ip_list.txt

# 指定報告輸出目錄
sudo python3 Easmscan.py ip_list.txt /path/to/report

# 不使用 sudo（可能無法執行某些深度掃描）
python3 Easmscan.py ip_list.txt
```

### 參數說明

1. **第一個參數（必填）**：目標清單檔案路徑
   - 格式：每行一個 IP 地址
   - 範例：`ip_list.txt`

2. **第二個參數（選填）**：報告輸出目錄
   - 預設值：`Report`
   - 範例：`/home/user/reports`

### 目標清單檔案格式

建立一個文字檔案（例如 `ip_list.txt`），每行一個 IP 地址：

```
8.8.8.8
1.1.1.1
192.168.1.1
example.com
```

### 執行範例

```bash
# 1. 建立目標清單
echo -e "8.8.8.8\n1.1.1.1" > ip_list.txt

# 2. 執行掃描（使用 sudo）
sudo python3 Easmscan.py ip_list.txt

# 3. 查看報告
ls -lh Report/
```

## 輸出說明

### Excel 報告檔案

報告檔案命名格式：`EASM_Report_YYYYMMDDHHmmss.xlsx`

### 工作表說明

1. **掃描摘要** (Executive Summary)
   - 目標受眾：管理者
   - 內容：全域統計數據（掃描日期、IP 總數、風險 IP 數、異動 IP 數等）

2. **漏洞清單** (Vulnerability List)
   - 目標受眾：資安工程師
   - 內容：只列出有問題的項目（IP、Port、漏洞類型、修補建議）

3. **變動比對** (Change Log)
   - 目標受眾：維運人員
   - 內容：與上次掃描的差異（新增 IP、Port 變動、服務版本變更等）

4. **Port 開啟統計** (Port Stats)
   - 目標受眾：網路管理員
   - 內容：各 Port 的開啟頻率統計

5. **詳細資料** (Raw Data)
   - 目標受眾：完整存檔
   - 內容：所有掃描到的原始資料總表

### 歷史記錄檔案

- 檔案名稱：`scan_history.json`
- 用途：記錄每次掃描的結果，用於比對變動
- 位置：與 `Easmscan.py` 同一目錄

## 進階設定

### 調整執行緒數

編輯 `Easmscan.py`，修改全域變數：

```python
# 執行緒池大小（預設值為 1，可調整）
MAX_WORKERS = 5  # 改為 5 個執行緒
```

**注意**：執行緒數過多可能導致系統負載過高或被防火牆封鎖，建議根據網路環境調整。

### Web 服務 Port 設定

如需修改 Web 服務 Port 清單，編輯 `Easmscan.py`：

```python
# Web 服務常用 Port
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 9000]  # 新增 9000
```

## 疑難排解

### 問題 1：權限不足

**錯誤訊息**：
```
[!] 深掃失敗: You requested a scan type which requires root privileges.
```

**解決方法**：
```bash
# 使用 sudo 執行
sudo python3 Easmscan.py ip_list.txt
```

### 問題 2：Nmap 未安裝

**錯誤訊息**：
```
ModuleNotFoundError: No module named 'nmap'
```

**解決方法**：
```bash
# 安裝 python-nmap（注意：不是 nmap）
pip3 install python-nmap
```

### 問題 3：GeoIP 查詢失敗

**現象**：地理位置顯示為 "N/A"

**原因**：可能是網路連線問題或 API 限制

**解決方法**：此為非關鍵功能，不影響掃描結果

### 問題 4：Excel 檔案中文亂碼

**解決方法**：確保系統支援 UTF-8 編碼，程式已使用 UTF-8 編碼處理

## 注意事項

1. **使用 sudo 執行**：深度掃描需要 root 權限，建議使用 `sudo` 執行
2. **掃描時間**：全 Port 掃描（1-65535）需要較長時間，請耐心等待
3. **網路負載**：大量掃描可能對網路造成負載，請在適當時間執行
4. **合法使用**：僅掃描您擁有或有權掃描的目標
5. **防火牆**：某些目標可能有防火牆保護，掃描結果可能不完整

## 授權與免責聲明

本工具僅供合法安全測試使用，使用者需自行承擔使用責任。

