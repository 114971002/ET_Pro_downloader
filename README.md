# ET Pro 自動下載器

此專案依 `proposal.md` 第一版需求建立，目標是在 Windows 電腦上每天台灣時間 00:00 自動下載 ET Pro Suricata 8.0 最新規則檔，完成檔案檢查後產出每日 CSV 分析報告，並保留後續篩濾與部署模組。

## 目錄結構

```text
etpro_auto_downloader/
  downloads/          # 下載的 ET Pro tar.gz
  logs/               # 執行與錯誤紀錄
  output/             # 篩濾後的 .rules 輸出
  deploy/             # 實際部署用 deploy.rules
  deploy/archive/     # 舊 deploy.rules 歸檔
  reports/            # 每日 CSV 分析報告
  src/                # Python 程式碼
  tests/              # 單元測試
```

## 安裝需求

請先確認 Windows 已安裝 Python，並可在 PowerShell 執行 `python --version`。

```powershell
cd C:\Users\user\codex-test\etpro_auto_downloader
python -m pip install -r requirements.txt
```

## 設定環境變數

此程式不會把 Oinkcode 寫在程式碼中，必須由 Windows 環境變數提供。

```powershell
setx ETPRO_OINKCODE "你的_OINKCODE"
```

`setx` 只會影響新開啟的終端機。若要讓目前 PowerShell 立即可用，可以另外執行：

```powershell
$env:ETPRO_OINKCODE="你的_OINKCODE"
```

預設部署路徑是：

```text
C:\Users\user\codex-test\etpro_auto_downloader\deploy\deploy.rules
```

若未來要改成其他部署路徑，可設定：

```powershell
setx ETPRO_DEPLOY_TARGET_PATH "C:\path\to\deploy.rules"
```

預設下載 Suricata 8.0 規則。若未來要改版本，可設定：

```powershell
setx ETPRO_SURICATA_VERSION "8.0"
```

目前篩濾標準尚未決定，因此程式會遍歷下載下來的 `.tar.gz` 內所有 `.rules` 檔，將未被 `#` 註解的行輸出成 `deploy.rules`。

若部署目標已存在，程式會先把舊的 `deploy.rules` 移到 `deploy/archive/YYYYMMDD_deploy.rules`，其中 `YYYYMMDD` 是前一日日期。若同日期的 archive 檔已存在，程式會停止並寫入 log。

## Suricata Dry-Run

部署前會用 Suricata `-T` 對暫存的 `deploy.rules` 做 dry-run 驗證。若驗證失敗，會直接拋出例外中斷流程並記錄詳細錯誤，此時**部署流程與舊檔清理均不會執行**，以確保系統中正在運行之規則不被損毀規則所覆蓋。

預設路徑：

```text
C:\Program Files\Suricata\suricata.exe
C:\Program Files\Suricata\suricata.yaml
C:\Windows\System32\Npcap
```

可用環境變數調整：

```powershell
setx ETPRO_SURICATA_VALIDATION_ENABLED "true"
setx ETPRO_SURICATA_EXE "C:\Program Files\Suricata\suricata.exe"
setx ETPRO_SURICATA_YAML "C:\Program Files\Suricata\suricata.yaml"
setx ETPRO_NPCAP_DIR "C:\Windows\System32\Npcap"
```

## 威脅情資同步設定

此專案整合了 MITRE ATT&CK 威脅情資同步模組 (`src/update_intel.py`)。預設情況下，排程器在每天啟動時，會自動從 MITRE 的 GitHub 儲存庫同步最新的入侵群組對應表（mappings）與軟體黑名單，產出對應的 JSON 設定檔並存放於 `config/` 目錄下（例如 `actor_mappings.json` 與 `software_denylist.json`），用於後續規則篩選機制。

### 環境變數設定

- **`ETPRO_INTEL_SYNC_ENABLED`**
  - **說明**：是否啟用威脅情資同步。預設為 `true`。
  - **適用場景**：在隔離網路環境（air-gapped）下，可將其設定為 `false` 以避開對外部網路的請求，系統將自動套用本地已有的快取或內建預設值。
  - **設定方式**：
    ```powershell
    setx ETPRO_INTEL_SYNC_ENABLED "false"
    ```

### 自訂覆寫與快取機制

1. **自訂覆寫 (`config/intel_overrides.json`)**
   使用者可以在 `config/intel_overrides.json` 中配置自訂的群組別名對應 (`actor_mappings`) 與軟體黑名單 (`software_denylist`)，同步程式在執行時會自動載入並與從 MITRE ATT&CK 取得的資料進行合併。
   例如：
   ```json
   {
       "actor_mappings": {
           "MyCustomGroup": ["custom-alias-1", "custom-alias-2"]
       },
       "software_denylist": [
           "my-custom-malware"
       ]
   }
   ```
2. **快取快照 (`config/mitre_attack_cache.json`)**
   當威脅情資更新成功後，會自動在本地將 MITRE ATT&CK 的原始 JSON 資料快取為 `mitre_attack_cache.json`。若未來網路連線中斷，程式會自動讀取此快取檔；若連快取檔也不存在，則會降級套用程式內建的靜態預設威脅情資。

## 網頁視覺化管理平台 Dashboard

本專案內建一個**零外部相依性（Zero-Dependency）**的輕量級網頁視覺化管理平台，提供高質感的深色玻璃擬態介面。

主要功能包括：
1. **系統監控**：顯示當前已部署規則數、自動修復屏蔽規則數、硬碟空間佔用與核心設定。
2. **手動執行管線**：提供「立即執行同步與下載」按鈕，可於背景執行緒中安全非同步執行完整更新管線，免去指令列手動執行的繁瑣。
3. **情資覆寫編修**：直接在線上進行 `actor_mappings.json`（群組對應）與 `software_denylist.json`（軟體黑名單）的讀寫與儲存。
4. **自動修復規則追蹤**：條列出當前所有因為語法出錯而被 Auto-Healing 自我修復機制加上註解屏蔽的規則（支援搜尋與過濾）。
5. **即時日誌檢視**：內建虛擬終端機控制台，每 3 秒自動同步拉取 `logs/download.log` 的最新內容。

### 啟動方式

在專案目錄下執行：

```powershell
python src\web_server_entry.py
```

預設會於本機 `http://127.0.0.1:8000` 開啟服務。

#### 自訂監聽位址與埠口

```powershell
python src\web_server_entry.py --host 0.0.0.0 --port 9000
```

## 手動執行

```powershell
cd C:\Users\user\codex-test\etpro_auto_downloader
python src\scheduler_entry.py
```

成功後會產生：

```text
downloads/YYYYMMDD_etpro.rules.tar.gz
reports/daily_analysis_YYYYMMDD.csv
deploy/deploy.rules
logs/download.log
```

若當天下載檔案已存在，程式目前會停止並記錄錯誤，不會覆蓋既有檔案。這個行為可避免在尚未確認覆蓋政策前破壞歷史檔案。

## Windows 工作排程器設定

建議使用 Windows 工作排程器每天 00:00 執行。

| 欄位 | 設定 |
| --- | --- |
| 觸發程序 | 每天 00:00 |
| 動作 | 啟動程式 |
| 程式或指令碼 | Python 執行檔路徑，例如 `C:\Users\user\AppData\Local\Programs\Python\Python312\python.exe` |
| 新增引數 | `src\scheduler_entry.py` |
| 起始位置 | `C:\Users\user\codex-test\etpro_auto_downloader` |

注意：排程執行時，Windows 電腦需要開機、可連網，且排程使用者必須讀得到 `ETPRO_OINKCODE`。

## 重試與紀錄

下載失敗後會重試 10 次，每次間隔 3 分鐘。也就是最多會進行 1 次初始下載加 10 次重試。

錯誤與執行資訊會寫入：

```text
logs/download.log
```

Log 中會遮蔽 Oinkcode，不會完整寫出授權碼。

程式只透過 log 紀錄錯誤與清理結果，不會寄送通知。

## 檔案保留策略

程式會在成功部署後清理歷史檔案：

| 類型 | 保留天數 |
| --- | --- |
| `downloads/*.tar.gz` | 30 天 |
| `reports/*.csv` | 90 天 |

刪除結果會寫入 `logs/download.log`。

## 模組說明

| 模組 | 職責 |
| --- | --- |
| `src/config.py` | 讀取環境變數、路徑、下載 URL 與日期命名 |
| `src/downloader.py` | 下載 ET Pro 規則、處理重試 |
| `src/validator.py` | 檢查 `.tar.gz` 是否有效並包含 `.rules` |
| `src/analyzer.py` | 解析 Suricata 規則並輸出 CSV |
| `src/rule_exporter.py` | 匯出所有未註解規則到 `deploy.rules` |
| `src/filter_engine.py` | 預留重要規則篩濾接口 |
| `src/suricata_validator.py` | 部署前執行 Suricata dry-run 驗證，失敗中斷部署並報錯 |
| `src/update_intel.py` | 同步 MITRE ATT&CK 威脅情資（威脅群組與惡意軟體名單）並合併自訂覆寫檔 |
| `src/web_server.py` | 網頁管理平台伺服器（包含 API 與前端介面） |
| `src/web_server_entry.py` | 網頁管理平台啟動進入點 |
| `src/deployer.py` | 部署 `deploy.rules`，並歸檔舊部署檔 |
| `src/retention.py` | 清理超過保留天數的下載檔與報告 |
| `src/scheduler_entry.py` | 排程器呼叫的主入口 |

## 測試

```powershell
cd C:\Users\user\codex-test\etpro_auto_downloader
python -m unittest discover -s tests
```

測試不會連線到 ET Pro，也不需要真實 Oinkcode。

## 系統重建指南 (System Reconstruction Guide)
若您需要在另一台電腦上重新部署本系統，請按照以下步驟執行：

1. **安裝必備環境**：確保新電腦已安裝 Git 與 Python (>=3.9)，安裝 Python 時請務必勾選 "Add python.exe to PATH"。
2. **下載專案**：在終端機執行 "git clone https://github.com/114971002/ET_Pro_downloader.git"，然後 "cd ET_Pro_downloader"。
3. **安裝套件**：執行 "pip install -r requirements.txt" 安裝所需依賴。
4. **設定環境變數**：系統需要您的 ET Pro Oinkcode 授權碼才能下載規則。請設定環境變數 ETPRO_OINKCODE (例如："setx ETPRO_OINKCODE 您的授權碼")。
5. **啟動網頁介面**：執行 "python src/web_server_entry.py"，開啟瀏覽器前往 "http://localhost:8000" 即可看到儀表板。
