"""
Bilingual Intelligence Translation Module for Threat Intelligence Hub.
Provides Traditional Chinese translations for MITRE ATT&CK techniques, tactics,
classtypes, severities, and curated intelligence summaries for threat actors.
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional

TECHNIQUE_TRANSLATIONS: Dict[str, str] = {
    # Base Techniques
    "T1001": "資料混淆傳輸 (Data Obfuscation)",
    "T1001.001": "資料混淆傳輸: 隱寫術 (Steganography)",
    "T1001.002": "資料混淆傳輸: 協定混淆 (Protocol Impersonation)",
    "T1003": "作業系統憑證轉儲 (OS Credential Dumping)",
    "T1003.001": "憑證轉儲: LSASS 記憶體 (LSASS Memory)",
    "T1003.002": "憑證轉儲: 安全帳戶管理員 (SAM Database)",
    "T1003.003": "憑證轉儲: NTDS.dit 雜湊提取",
    "T1003.004": "憑證轉儲: LSA 密碼金鑰 secrets",
    "T1003.005": "憑證轉儲: 快取的網域憑證 (Cached Domain Credentials)",
    "T1003.006": "憑證轉儲: DCSync 網域複寫攻擊",
    "T1005": "本地系統資料收集 (Data from Local System)",
    "T1007": "系統服務探查 (System Service Discovery)",
    "T1012": "查詢系統登錄檔 (Query Registry)",
    "T1016": "系統網路配置探查 (System Network Configuration)",
    "T1016.001": "網路介面與連線探查 (Internet Connection Discovery)",
    "T1018": "遠端主機探查 (Remote System Discovery)",
    "T1021": "遠端服務存取 (Remote Services)",
    "T1021.001": "遠端桌面協定存取 (Remote Desktop Protocol / RDP)",
    "T1021.002": "SMB / Windows 管理共用 (SMB/Windows Admin Shares)",
    "T1021.004": "安全殼層遠端連線 (SSH)",
    "T1021.006": "Windows 遠端管理 (Windows Remote Management / WinRM)",
    "T1027": "混淆檔案或資訊 (Obfuscated Files or Information)",
    "T1027.001": "二進制二階填充 (Binary Padding)",
    "T1027.002": "軟體加殼封裝 (Software Packing)",
    "T1027.003": "隱藏程式碼內聯字串 (Steganography in Code)",
    "T1027.004": "編譯後代碼混淆 (Compile After Delivery)",
    "T1027.005": "指標去除與代碼符號混淆 (Indicator Removal)",
    "T1027.013": "檔案加密或編碼 (Encrypted/Encoded File)",
    "T1033": "系統擁有者與使用者探查 (System Owner/User Discovery)",
    "T1036": "惡意偽裝與偽造 (Masquerading)",
    "T1036.001": "無效代碼簽署 (Invalid Code Signature)",
    "T1036.003": "重命名合法系統工具 (Rename Legitimate Utilities)",
    "T1036.004": "偽裝系統檔名與路徑 (Masquerading Task or Path)",
    "T1036.005": "仿冒合法資源名稱 (Match Legitimate Resource Name)",
    "T1036.006": "檔名後置空格偽裝 (Space after Filename)",
    "T1036.007": "雙重副檔名偽裝 (Double File Extension)",
    "T1037": "開機或登入初始化腳本 (Boot or Logon Initialization Scripts)",
    "T1040": "網路封包監聽 (Network Sniffing)",
    "T1041": "經由 C2 通道資料外洩 (Exfiltration Over C2 Channel)",
    "T1046": "網路服務探查 (Network Service Discovery)",
    "T1047": "Windows 管理規範 (WMI)",
    "T1048": "經由替代協定外洩 (Exfiltration Over Alternative Protocol)",
    "T1049": "系統網路連線探查 (System Network Connections Discovery)",
    "T1053": "排程任務 / 工作執行 (Scheduled Task/Job)",
    "T1053.003": "排程工作: Cron (Cron Job)",
    "T1053.005": "排程工作: Windows 排程任務 (Scheduled Task)",
    "T1055": "處理程序注入 (Process Injection)",
    "T1055.001": "動態程式庫注入 (Dynamic-link Library Injection)",
    "T1055.002": "可移植執行檔注入 (Portable Executable Injection)",
    "T1055.012": "處理程序空洞化 (Process Hollowing)",
    "T1056": "輸入捕獲與鍵盤記錄 (Input Capture)",
    "T1056.001": "鍵盤記錄器 (Keylogging)",
    "T1057": "處理程序發現 (Process Discovery)",
    "T1059": "命令與腳本直譯器 (Command and Scripting Interpreter)",
    "T1059.001": "PowerShell 腳本直譯器 (PowerShell)",
    "T1059.003": "Windows 命令列直譯器 (Windows Command Shell / cmd)",
    "T1059.004": "Unix 殼層腳本 (Unix Shell / bash)",
    "T1059.005": "Visual Basic 腳本 (Visual Basic / VBScript)",
    "T1059.006": "Python 腳本直譯器 (Python)",
    "T1059.007": "JavaScript 腳本直譯器 (JavaScript)",
    "T1070": "指標清除與反數位鑑識 (Indicator Removal on Host)",
    "T1070.004": "檔案刪除與反鑑識 (File Deletion)",
    "T1071": "應用層通訊協定 (Application Layer Protocol)",
    "T1071.001": "Web 應用協定 (Web Protocols HTTP/HTTPS)",
    "T1071.002": "檔案傳輸協定 (File Transfer Protocols FTP/SFTP)",
    "T1071.003": "郵件傳輸協定 (Mail Protocols SMTP/IMAP)",
    "T1071.004": "域名解析協定 (DNS Protocols)",
    "T1072": "軟體部署工具濫用 (Software Deployment Tools)",
    "T1074.001": "本地資料暫存暫留 (Local Data Staging)",
    "T1078": "有效帳戶濫用 (Valid Accounts)",
    "T1082": "系統資訊探查 (System Information Discovery)",
    "T1083": "檔案與目錄探查 (File and Directory Discovery)",
    "T1087.001": "本機帳號探查 (Local Account Discovery)",
    "T1087.002": "網域帳號探查 (Domain Account Discovery)",
    "T1090": "代理伺服器轉發 (Proxy)",
    "T1095": "非應用層通訊協定傳輸 (Non-Application Layer Protocol)",
    "T1102": "外部 Web 服務利用 (Web Service)",
    "T1105": "入口工具傳輸 / 載入器 (Ingress Tool Transfer)",
    "T1106": "原生作業系統 API 呼叫 (Native API)",
    "T1110": "密碼暴力破解 (Brute Force)",
    "T1112": "修改系統登錄檔 (Modify Registry)",
    "T1113": "螢幕截圖捕獲 (Screen Capture)",
    "T1114": "電子郵件收集 (Email Collection)",
    "T1114.001": "本地郵件收集 (Local Email Collection)",
    "T1114.002": "郵件伺服器查詢收集 (Remote Email Collection)",
    "T1132": "資料編碼傳輸 (Data Encoding)",
    "T1132.001": "標準編碼傳輸 Base64 (Standard Encoding)",
    "T1140": "檔案或情資去混淆與解碼 (Deobfuscate/Decode Files or Information)",
    "T1189": "路過式下載攻擊 (Drive-by Compromise)",
    "T1190": "利用對外公開應用程式弱點 (Exploit Public-Facing Application)",
    "T1203": "客戶端弱點利用 (Exploitation for Client Execution)",
    "T1204": "使用者執行惡意操作 (User Execution)",
    "T1204.001": "使用者點擊惡意連結 (Malicious Link)",
    "T1204.002": "使用者執行惡意檔案 (Malicious File)",
    "T1205": "流量訊號觸發 (Traffic Signaling / Port Knocking)",
    "T1210": "遠端服務弱點利用 (Exploitation of Remote Services)",
    "T1218.011": "Rundll32 代理執行 (Rundll32 Execution)",
    "T1219": "遠端存取軟體利用 (Remote Access Software)",
    "T1486": "資料加密破壞 / 勒索軟體 (Data Encrypted for Impact)",
    "T1490": "抑制系統還原功能 (Inhibit System Recovery)",
    "T1496": "運算資源劫持 (Resource Hijacking / 挖礦)",
    "T1498": "網路阻斷服務攻擊 (Network Denial of Service / DoS)",
    "T1505": "伺服器軟體組件 / Web Shell (Server Software Component)",
    "T1518.001": "資安防護軟體探查 (Security Software Discovery)",
    "T1543.003": "Windows 服務建立與持久化 (Windows Service)",
    "T1547": "開機或登入自動執行 (Boot or Logon Autostart Execution)",
    "T1547.001": "註冊表啟動機碼 / 啟動資料夾 (Registry Run Keys / Startup Folder)",
    "T1552": "未加密憑證搜尋 (Unsecured Credentials)",
    "T1557": "攔截中間人攻擊 (Adversary-in-the-Middle / AiTM)",
    "T1560": "收集資料壓縮封裝 (Archive Collected Data)",
    "T1562": "削弱安全防禦機制 (Impair Defenses)",
    "T1566": "網路釣魚攻擊 (Phishing)",
    "T1566.001": "魚叉式釣魚郵件夾帶惡意附件 (Spearphishing Attachment)",
    "T1566.002": "魚叉式釣魚郵件夾帶惡意連結 (Spearphishing Link)",
    "T1566.003": "透過第三方服務發動釣魚 (Spearphishing via Service)",
    "T1567": "經由 Web 服務外洩 (Exfiltration Over Web Service)",
    "T1568": "動態解析通訊 (Dynamic Resolution / Fast Flux / DGA)",
    "T1570": "橫向工具傳輸 (Lateral Tool Transfer)",
    "T1571": "非標準連接埠通訊 (Non-Standard Port)",
    "T1572": "協定穿透與通道穿隧 (Protocol Tunneling)",
    "T1573": "加密通訊通道 (Encrypted Channel)",
    "T1573.001": "對稱加密通訊通道 (Symmetric Cryptography)",
    "T1573.002": "非對稱加密通訊通道 (Asymmetric Cryptography)",
    "T1574.001": "DLL 劫持與側載 (DLL Side-Loading)",
    "T1574.002": "DLL 載入搜尋順序劫持 (DLL Search Order Hijacking)",
    "T1583": "獲取攻擊基礎設施 (Acquire Infrastructure)",
    "T1587": "發展攻擊武器化能力 (Develop Capabilities)",
    "T1588.002": "獲取現成攻擊工具 (Tool Acquisition)",
    "T1590": "收集受害者網路資訊 (Gather Victim Network Information)",
    "T1593": "搜尋開放網路情資 (Search Open Websites/Domains)",
    "T1614": "系統地理位置探查 (System Location Discovery)",
    "T1665": "隱藏攻擊基礎設施 (Hide Infrastructure)",
    "T1680": "本地儲存裝置探查 (Local Storage Discovery)",
    "T1685": "停用或修改防護工具 (Disable or Modify Tools)",
}

TACTIC_TRANSLATIONS: Dict[str, str] = {
    "reconnaissance": "偵察 (Reconnaissance)",
    "resource-development": "資源開發 (Resource Development)",
    "initial-access": "初始存取 (Initial Access)",
    "execution": "執行 (Execution)",
    "persistence": "持續性滲透 (Persistence)",
    "privilege-escalation": "權限提升 (Privilege Escalation)",
    "defense-evasion": "防禦繞過 (Defense Evasion)",
    "stealth": "隱匿匿蹤 (Stealth)",
    "credential-access": "憑證存取 (Credential Access)",
    "discovery": "內部探查 (Discovery)",
    "lateral-movement": "橫向移動 (Lateral Movement)",
    "collection": "資料收集 (Collection)",
    "command-and-control": "指令與控制 (Command and Control)",
    "exfiltration": "資料外洩 (Exfiltration)",
    "impact": "衝擊破壞 (Impact)",
}

CLASSTYPE_TRANSLATIONS: Dict[str, str] = {
    "trojan-activity": "木馬活動特徵 (trojan-activity)",
    "attempted-user": "嘗試取得使用者權限 (attempted-user)",
    "attempted-admin": "嘗試取得管理員權限 (attempted-admin)",
    "successful-admin": "成功取得管理員權限 (successful-admin)",
    "web-application-attack": "Web 應用程式攻擊 (web-application-attack)",
    "web-application-activity": "Web 應用程式存取活動 (web-application-activity)",
    "misc-attack": "各類網路攻擊特徵 (misc-attack)",
    "misc-activity": "各類異常網路活動 (misc-activity)",
    "policy-violation": "企業安全政策違規 (policy-violation)",
    "suspicious-filename-detect": "可疑惡意檔名偵測 (suspicious-filename-detect)",
    "bad-unknown": "未知潛在惡意流量 (bad-unknown)",
    "default-login-attempt": "預設帳號密碼登入嘗試 (default-login-attempt)",
    "network-scan": "網路埠號與主機掃描 (network-scan)",
    "denial-of-service": "阻斷服務攻擊 (denial-of-service)",
    "shellcode-detect": "Shellcode 惡意代碼偵測 (shellcode-detect)",
    "successful-recon-limited": "情報探查成功-有限 (successful-recon-limited)",
    "successful-recon-largescale": "大規模情報探查成功 (successful-recon-largescale)",
    "not-suspicious": "非可疑流量 (not-suspicious)",
    "unsuccessful-user": "使用者登入嘗試失敗 (unsuccessful-user)",
    "crypto-mining": "加密貨幣挖礦活動 (crypto-mining)",
    "credential-theft": "身分憑證竊取活動 (credential-theft)",
    "phishing": "網路釣魚活動 (phishing)",
    "command-and-control": "指令與控制連線 (command-and-control)",
    "targeted-activity": "定向攻擊滲透活動 (targeted-activity)",
}

SEVERITY_TRANSLATIONS: Dict[str, str] = {
    "critical": "嚴重 (Critical)",
    "major": "高 (Major)",
    "minor": "中 (Minor)",
    "informational": "資訊 (Informational)",
    "unknown": "未指定 (Unknown)",
}

ACTOR_ZH_PROFILES: Dict[str, str] = {
    "ta4903": (
        "TA4903 是一個以經濟利益為導向的高活躍度進階網路犯罪組織。"
        "該組織以針對美國政府機構及跨領域民間企業實施大規模「憑證釣魚（Credential Phishing）」"
        "與「商業電子郵件詐騙（BEC, Business Email Compromise）」而聞名。"
        "其攻擊手法具有高度欺騙性，經常註冊與受害組織客戶或供應商高度相似的仿冒網域，"
        "並率先採用包含 QR Code（Quishing 條碼釣魚）的詐騙信件繞過傳統電子郵件閘道安全防護，"
        "誘騙員工掃描並導向偽造登入頁面以竊取企業金融帳戶與 Microsoft 365 / Google Workspace 憑證。"
    ),
    "ta584": (
        "TA584 是長期活躍的惡意軟體散布團夥，主要作為初始存取代理人（Initial Access Broker）角色運行。"
        "該組織擅長利用加密通訊通道（T1573）與多階段混淆腳本傳遞遠端存取木馬（RAT），"
        "特別是大規模運用 XWorm RAT 與各類資訊竊取木馬（Infostealers），"
        "藉此在受害主機建立持久後門、截取鍵盤輸入並伺機向勒索軟體集團出售進入受害網路的存取權限。"
    ),
    "apt35": (
        "APT35（別名 Charming Kitten、Phosphorus、TA453）為歸屬於伊朗（IR）伊斯蘭革命衛隊（IRGC）的國家級 APT 組織。"
        "長期針對中東、美國、歐洲各國之外交官員、國防包商、人權組織、智庫、記者與學術研究人員發動精準滲透。"
        "該組織極具社交工程耐性，經常偽裝成研討會邀請、記者訪談，並透過魚叉式釣魚郵件、惡意連結"
        "與多重身分驗證（MFA）繞過技術滲透目標網路以刺探戰略機密。"
    ),
    "mustardtempest": (
        "Mustard Tempest（別名 TA569）為全球最具破壞力的網路犯罪與初始存取組織之一。"
        "最著名特徵為其掌控的 SocGholish 惡意傳遞系統——透過入侵合法熱門網站並注入惡意 JavaScript 代碼，"
        "對造訪使用者彈出偽造的瀏覽器更新提示（Fake Browser Update）。"
        "一旦使用者點擊，即會植入 GhoLoader、AsyncRAT 等惡意酬載，並為其他頂級勒索軟體團夥（如 Evil Corp）開拓入侵通道。"
    ),
    "tag124": (
        "TAG-124 是一個專門實施惡意搜尋引擎廣告（Malvertising）與路過式下載（Drive-by Compromise, T1189）的威脅集團。"
        "該組織購買搜尋引擎廣告將常用工具（如 WinRAR、AnyDesk、Notepad++）的搜尋結果導向偽造官網，"
        "誘騙使用者下載夾帶 NetSupport RAT 遠端控制軟體的安裝檔，取得受害系統之完整操控權限。"
    ),
    "aptc23": (
        "APT-C-23（別名 Arid Viper）為長期活躍於中東地區的巴勒斯坦背景進階威脅組織。"
        "主要鎖定政府、軍事、情報與媒體從業人員，具備自主開發 Windows 與 Android 雙平台間諜軟體的能力（如 Micropsia、AridGnat），"
        "攻擊載體常偽裝成 Telegram / WhatsApp 更新、軍事情報文件或應用程式以實施全方位通訊監控與錄音竊聽。"
    ),
    "ta444": (
        "TA444 是隸屬於北韓（DPRK / KP）RGB 偵察總局旗下 Lazarus 集團的特定任務分支小組。"
        "專門針對全球加密貨幣交易所、DeFi 去中心化金融協定、創投公司與區塊鏈開發者實施金融竊盜與憑證收割。"
        "其常用 CosmicRust、ProcessRequest 等跨平台惡意軟體，並在 LinkedIn 偽裝高薪獵頭誘騙工程師執行惡意測試專案。"
    ),
    "apt28": (
        "APT28（別名 Fancy Bear、Sofacy、Sednit、STRONTIUM）為俄羅斯聯邦武裝力量總參謀部情報總局（GRU）第 85 特別服務中心第 26165 部隊。"
        "自 2004 年以來持續對北約成員國、國防軍事機構、能源電網及國際組織發動戰略性網路間諜攻擊。"
        "擁有龐大的專用惡意軟體庫（Drovorub、X-Agent、Sofacy），精通零日弱點利用、韌體級 Rootkit 與進階 C2 隱匿架構。"
    ),
    "cobaltgroup": (
        "Cobalt Group 是一個極具破壞力的全球跨國網路金融犯罪集團。"
        "主要鎖定銀行與金融機構的 ATM 提款機控制系統、SWIFT 交易網路與銀行內部支付網關。"
        "透過高度特製化的 Cobalt Strike Beacon 與 More_eggs 惡意載荷實施深層橫向移動，曾對全球數十個國家的金融機構造成重大損失。"
    ),
    "uac0215": (
        "UAC-0215 為針對東歐與烏克蘭國家關鍵基礎設施、政府部會與能源部門發起精準破壞的進階威脅組織。"
        "攻擊者擅長運用專用 C2 協議與隱密憑證竊取技術，配合客製化後門軟體實施長時間的潛伏刺探與網路破壞活動。"
    ),
    "gamaredon": (
        "Gamaredon（別名 Primitive Bear、UAC-0010）為俄羅斯聯邦安全局（FSB）轄下之網路行動部隊。"
        "其特點為高頻率、大批量的魚叉式釣魚與動態基礎架構變更，針對烏克蘭軍事、國防與政府部門實施不間斷的情報偵蒐與文檔外洩。"
    ),
    "magecart": (
        "MageCart 為多個專門實施「數位側錄（Digital Skimming / e-Skimming）」犯罪集團的統稱。"
        "主要透過入侵電子商務網站（如 Magento、WordPress WooCommerce）並注入惡意 JavaScript 腳本，"
        "在消費者結帳結算時即時盜取信用卡卡號、過期日與 CVV 安全碼。"
    ),
    "mustangpanda": (
        "Mustang Panda（別名 RedDelta、BRONZE LYCHEE）為長期活躍的國家級網路間諜組織。"
        "主要鎖定亞太地區、東南亞國協（ASEAN）成員國及歐洲各國之政府、非政府組織（NGO）與宗教團體。"
        "慣用偽裝成官方紅頭文件或外交照會的惡意 LNK 捷徑與 DLL 側載（Side-loading）技術植入 PlugX / Korplug 遠端存取木馬。"
    ),
    "kimsuky": (
        "Kimsuky（別名 Velvet Chollima、Black Banshee）為北韓（KP）情報總局轄下的網路部隊。"
        "專責針對南韓、美國及日本的智庫專家、外交官、脫北者與核能防務專家發動長期的戰略情報蒐集。"
        "擅長撰寫逼真的學術論文評閱或新聞稿誘騙信件，並透過惡意巨集文檔與 Google Chrome 惡意擴充功能竊取機密。"
    ),
    "lazarus": (
        "Lazarus Group（別名 Hidden Cobra、Andariel、APT38）為北韓最具代表性的最高級別網路作戰單位。"
        "其攻擊涵蓋破壞性毀滅攻擊（如 2014 年 Sony 影業攻擊）、大規模蠕蟲勒索（2017 年 WannaCry）"
        "以及數十億美元規模的全球央行 SWIFT 轉帳系統與 Web3 加密貨幣搶劫案。"
    ),
    "winnti": (
        "Winnti Group（別名 APT41、Barium、Double Dragon）為兼具國家級間諜刺探與個人金融犯罪雙重任務的高階組織。"
        "擅長精準供應鏈攻擊（Supply Chain Attack），曾入侵多家電玩遊戲開發商、軟體供應商之建置伺服器並簽署官方數位憑證散布後門。"
    ),
    "turla": (
        "Turla（別名 Waterbug、Venomous Bear、Uroburos）為俄羅斯聯邦安全局（FSB）關聯之頂尖網路間諜組織。"
        "技術極為精湛，曾利用劫持商業衛星通訊下行鏈路（Satellite C2）以完全隱匿其真實 C2 伺服器地理位置，長期刺探各國軍政機密。"
    ),
    "sandworm": (
        "Sandworm（別名 TeleBots、APT44）為隸屬於俄羅斯 GRU 的軍事級破壞性網路戰團夥。"
        "曾發動全球首例導致大規模電網癱瘓的烏克蘭變電所攻擊（BlackEnergy）、NotPetya 毀滅性擦除軟體及 Olympic Destroyer 奧運攻擊。"
    )
}

def clean_stix_text(text: str) -> str:
    """Cleans STIX markdown links and academic citations for neat presentation."""
    if not text:
        return ""
    # Strip markdown links: [Text](url) -> Text
    s = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    # Strip citations: (Citation: ...) or [Citation: ...]
    s = re.sub(r"\([Cc]itation:[^\)]+\)", "", s)
    s = re.sub(r"\[[Cc]itation:[^\]]+\]", "", s)
    # Collapse multiple newlines & spaces
    s = re.sub(r"\n{3,}", "\n\n", s)
    s = re.sub(r"[ \t]+", " ", s)
    return s.strip()

def get_technique_zh_name(tech_id: str) -> str:
    """Returns Traditional Chinese name for a MITRE technique or sub-technique."""
    if not tech_id:
        return ""
    # Exact sub-technique match first
    if tech_id in TECHNIQUE_TRANSLATIONS:
        return TECHNIQUE_TRANSLATIONS[tech_id]
    # Fallback to parent technique
    base_id = tech_id.split(".")[0] if "." in tech_id else tech_id
    return TECHNIQUE_TRANSLATIONS.get(base_id, "")

def get_tactic_zh_name(shortname: str) -> str:
    """Returns Traditional Chinese name for a MITRE tactic with robust slug matching."""
    if not shortname:
        return ""
    slug = shortname.lower().strip().replace(" ", "-").replace("_", "-")
    return TACTIC_TRANSLATIONS.get(slug, shortname)

def get_classtype_zh(classtype: str) -> str:
    """Returns Traditional Chinese display name for a Suricata classtype."""
    if not classtype:
        return ""
    slug = classtype.lower().strip()
    return CLASSTYPE_TRANSLATIONS.get(slug, classtype)

def get_severity_zh(severity: str) -> str:
    """Returns Traditional Chinese display name for signature severity."""
    if not severity:
        return ""
    slug = severity.lower().strip()
    return SEVERITY_TRANSLATIONS.get(slug, severity)

def get_actor_zh_summary(actor_name: str, aliases: Optional[List[str]] = None, en_description: str = "") -> str:
    """Returns a tailored Traditional Chinese intelligence profile for a threat actor."""
    def norm(s: str) -> str:
        return re.sub(r"[^a-z0-9]", "", s.lower())

    search_keys = [norm(actor_name)]
    if aliases:
        for al in aliases:
            search_keys.append(norm(al))

    for key in search_keys:
        for profile_key, summary in ACTOR_ZH_PROFILES.items():
            if profile_key in key or key in profile_key:
                return summary

    return synthesize_zh_description(actor_name, en_description)

def synthesize_zh_description(name: str, en_desc: str) -> str:
    """Intelligently synthesizes a Traditional Chinese intelligence brief matching the English content."""
    clean_en = clean_stix_text(en_desc)
    if not clean_en:
        return (
            f"{name} 為 Proofpoint ET Pro 與威脅情資庫重點監控之活動群組。"
            f"在目前的 Suricata 規則體系中，已全面納入其特徵特異性 C2 通訊特徵、惡意載荷散布與憑證防禦規則。"
        )

    # Attribution / Country
    country = ""
    if re.search(r"iran|iranian|irgc", clean_en, re.I):
        country = "伊朗國家情報背景"
    elif re.search(r"russia|russian|gru|fsb|svr", clean_en, re.I):
        country = "俄羅斯國家安全或軍事情報背景"
    elif re.search(r"china|chinese|prc|mss", clean_en, re.I):
        country = "中國國家背景之進階網路間諜"
    elif re.search(r"north korea|dprk|korean|lazarus", clean_en, re.I):
        country = "北韓國家級網路作戰"
    elif re.search(r"vietnam|vietnamese|oceanlotus", clean_en, re.I):
        country = "越南背景之進階威脅"
    elif re.search(r"palestin|gaza|arid viper", clean_en, re.I):
        country = "巴勒斯坦背景"

    # Motives
    motives = []
    if re.search(r"financially motivated|financial gain|monetary|extortion", clean_en, re.I):
        motives.append("經濟利益與資產盜取")
    if re.search(r"espionage|intelligence collection|strategic", clean_en, re.I):
        motives.append("國家級情報刺探與戰略間諜活動")
    if re.search(r"destructive|sabotage|wiper|data wiping", clean_en, re.I):
        motives.append("毀滅性破壞與網路癱瘓行動")

    # Target Sectors
    targets = []
    if re.search(r"government|ministr|diplomat|embass|public sector", clean_en, re.I):
        targets.append("政府部會與外交使館")
    if re.search(r"military|defense|armed forces", clean_en, re.I):
        targets.append("國防軍事與防務承包商")
    if re.search(r"aerospace|aviation", clean_en, re.I):
        targets.append("航太科技與航空工業")
    if re.search(r"financial|bank|banking|crypto|fintech", clean_en, re.I):
        targets.append("金融銀行與加密貨幣產業")
    if re.search(r"critical infrastructure|energy|power grid|oil|gas|telecom", clean_en, re.I):
        targets.append("關鍵基礎設施、能源電網與電信")
    if re.search(r"academic|think tank|research|higher education|journalist", clean_en, re.I):
        targets.append("學術智庫、人權團體與媒體機構")
    if re.search(r"supply chain|software developer|vendor", clean_en, re.I):
        targets.append("軟體供應鏈與 IT 服務商")

    # Attack Vectors
    vectors = []
    if re.search(r"spearphishing|phishing|credential harvesting", clean_en, re.I):
        vectors.append("魚叉式郵件釣魚與身分憑證竊取")
    if re.search(r"drive-by|malvertising|traffic distribution|fake update", clean_en, re.I):
        vectors.append("偽造更新、惡意廣告與路過式下載")
    if re.search(r"ransomware", clean_en, re.I):
        vectors.append("勒索軟體加密與雙重敲詐")
    if re.search(r"vulnerabilit|exploit|zero-day", clean_en, re.I):
        vectors.append("已知公開漏洞或零日弱點利用")
    if re.search(r"social engineering|linkedin", clean_en, re.I):
        vectors.append("社交網路工程誘騙")
    if re.search(r"dll side|side-loading", clean_en, re.I):
        vectors.append("DLL 側載惡意載荷")

    sentences = []
    intro = f"{name} 為受到全球資安情資社群密切追蹤的進階持續性威脅（APT）組織"
    if country:
        intro += f"（具備{country}特徵）"
    if motives:
        m_str = "與".join(motives)
        intro += f"，主要行動動機為{m_str}。"
    else:
        intro += "。"
    sentences.append(intro)

    if targets:
        t_str = "、".join(targets[:4])
        sentences.append(f"其主要鎖定之目標產業與機構涵蓋：{t_str}。")

    if vectors:
        v_str = "、".join(vectors[:4])
        sentences.append(f"常見入侵途徑與攻擊戰術包含：{v_str}。")

    sentences.append("在當前 Suricata 防禦體系中，已全面收錄其已知 C2 通訊特徵、惡意載荷網域與對應阻斷規則。")
    return " ".join(sentences)
