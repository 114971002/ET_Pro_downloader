// ET Pro Auto Downloader Dashboard Application

let globalInitData = null;
let currentTab = "dashboard";

// Active Rules state
let activeRulesPage = 1;
let activeRulesLimit = 25;
let activeRulesDebounceTimer = null;

// Disabled Rules state
let disabledRulesPage = 1;
let disabledRulesLimit = 25;
let allDisabledRules = [];

// Threat Intel state
let allThreatActors = [];
let selectedActorId = null;

// CTI Blocklist state
let ctiPage = 1;
let ctiLimit = 25;
let ctiDebounceTimer = null;

// GeoIP state
let geoipMap = null;
let geoipTileLayer = null;
let geoipCurrentTheme = "dark";
let geoipMarkers = [];
let geoipLines = [];

// CodeMirror & SSE
let logEventSource = null;

// Helper: Fetch JSON with error handling
async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, options);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || res.statusText);
    }
    return await res.json();
  } catch (e) {
    console.error(`API Fetch error [${url}]:`, e);
    throw e;
  }
}

// -------------------------------------------------------------
// TAB SWITCHING
// -------------------------------------------------------------
function switchTab(tabId) {
  currentTab = tabId;
  document.querySelectorAll(".nav-item").forEach(item => {
    item.classList.remove("active");
  });
  
  // Activate nav link
  const navLink = document.querySelector(`a[onclick*="switchTab('${tabId}')"]`);
  if (navLink) navLink.classList.add("active");

  document.querySelectorAll(".tab-content").forEach(content => {
    content.classList.remove("active");
  });
  const target = document.getElementById(tabId);
  if (target) target.classList.add("active");

  // Route-specific triggers
  if (tabId === "dashboard") {
    fetchStatus();
  } else if (tabId === "rules-tab") {
    fetchDisabledRules();
  } else if (tabId === "deployed-rules-tab") {
    fetchDeployedRules(true);
  } else if (tabId === "intel-tab") {
    fetchThreatActors();
  } else if (tabId === "cti-tab") {
    fetchCtiStatus();
    initCtiFilters();
    applyCtiFilters(true);
  } else if (tabId === "rollback-tab") {
    fetchDeployments();
  } else if (tabId === "logs-tab") {
    fetchLogs();
  } else if (tabId === "geoip-tab") {
    initGeoIPMap();
    setTimeout(() => {
      if (geoipMap) geoipMap.invalidateSize();
    }, 150);
  } else if (tabId === "suricata-config-tab") {
    fetchSuricataYaml();
  } else if (tabId === "config-tab") {
    fetchConfig();
  }
}

// -------------------------------------------------------------
// DASHBOARD
// -------------------------------------------------------------
async function fetchStatus() {
  try {
    const data = await apiFetch("/api/system/init_data");
    globalInitData = data;
    const status = data.status || {};
    const health = data.health || {};
    const stats = data.stats || {};
    const facets = data.facets || {};

    // Sidebar status
    const sidebarStatus = document.getElementById("sidebar-status");
    if (sidebarStatus) {
      const isRunning = status.status === "running";
      sidebarStatus.textContent = isRunning ? "執行中" : "正常運作 (idle)";
      sidebarStatus.className = `status-badge ${isRunning ? "running" : "idle"}`;
    }
    const sidebarLastRun = document.getElementById("sidebar-last-run");
    if (sidebarLastRun) {
      sidebarLastRun.textContent = status.last_run_time || "無";
    }

    // Disk space
    if (health.disk) {
      const percent = Math.min(100, Math.max(0, Math.round(health.disk.percent || 0)));
      const diskPercent = document.getElementById("disk-usage-percent");
      if (diskPercent) diskPercent.textContent = `${percent}%`;

      const diskBar = document.getElementById("disk-usage-bar");
      if (diskBar) diskBar.style.width = `${percent}%`;

      const usedEl = document.getElementById("disk-used-text");
      if (usedEl) usedEl.textContent = `已使用: ${health.disk.used || "-"}`;
      const freeEl = document.getElementById("disk-free-text");
      if (freeEl) freeEl.textContent = `可用: ${health.disk.free || "-"}`;
      const totalEl = document.getElementById("disk-total-text");
      if (totalEl) totalEl.textContent = `總容量: ${health.disk.total || "-"}`;
    }

    // Four Stat Cards
    const actRules = document.getElementById("stat-active-rules");
    if (actRules) actRules.textContent = (status.total_rules || 0).toLocaleString();

    const disRules = document.getElementById("stat-disabled-rules");
    if (disRules) disRules.textContent = (status.disabled_rules_count || 0).toLocaleString();

    const runStat = document.getElementById("stat-run-status");
    if (runStat) {
      if (status.last_run_time) {
        runStat.textContent = status.last_run_success ? "同步成功" : "同步失敗";
        runStat.style.color = status.last_run_success ? "var(--accent-green)" : "var(--accent-red)";
      } else {
        runStat.textContent = status.status === "running" ? "執行中..." : "尚未執行";
        runStat.style.color = "var(--text-primary)";
      }
    }
    const runDesc = document.getElementById("stat-run-desc");
    if (runDesc) {
      runDesc.textContent = status.last_run_time ? `最後同步: ${status.last_run_time}` : "尚未進行首次下載同步";
    }

    const storageSize = document.getElementById("stat-storage-size");
    if (storageSize) {
      storageSize.textContent = `下載: ${status.downloads_dir_size || "0 B"} | 報告: ${status.reports_dir_size || "0 B"}`;
    }

    // Core environment settings
    const envDeploy = document.getElementById("env-deploy-path");
    if (envDeploy) envDeploy.textContent = status.deploy_target_path || "-";

    const envOink = document.getElementById("env-oinkcode-status");
    if (envOink) {
      envOink.innerHTML = status.oinkcode_configured
        ? '<span style="color: var(--accent-green); font-weight: 600;"><i class="fa-solid fa-circle-check"></i> 已設定 (Configured)</span>'
        : '<span style="color: var(--accent-orange); font-weight: 600;"><i class="fa-solid fa-triangle-exclamation"></i> 未設定 (請至環境變數設定 ETPRO_OINKCODE)</span>';
    }

    const envIntel = document.getElementById("env-intel-sync");
    if (envIntel) {
      envIntel.textContent = status.intel_sync_enabled ? "已啟用 (Enabled)" : "已停用 (Disabled)";
    }

    const envVal = document.getElementById("env-validation");
    if (envVal) {
      envVal.textContent = status.validation_enabled ? "已啟用 (Enabled)" : "已停用 (Disabled)";
    }

    // Populate facets dropdowns for Deployed Rules tab
    populateFacetsDropdowns(facets);

    // Render distribution stats
    renderAllStats();

  } catch (e) {
    console.error("fetchStatus failed:", e);
  }
}

const TACTIC_BILINGUAL = {
  "Command And Control": "指令與控制 (Command and Control)",
  "Initial Access": "初始存取 (Initial Access)",
  "Exfiltration": "資料外洩 (Exfiltration)",
  "Defense Evasion": "防禦繞過 (Defense Evasion)",
  "Resource Development": "資源開發 (Resource Development)",
  "Impact": "衝擊破壞 (Impact)",
  "Discovery": "內部探查 (Discovery)",
  "Lateral Movement": "橫向移動 (Lateral Movement)",
  "Collection": "資料收集 (Collection)",
  "Persistence": "持續性滲透 (Persistence)",
  "Reconnaissance": "偵察 (Reconnaissance)",
  "Execution": "執行 (Execution)",
  "Credential Access": "憑證存取 (Credential Access)",
  "Privilege Escalation": "權限提升 (Privilege Escalation)"
};

const SEVERITY_BILINGUAL = {
  "Critical": "嚴重 (Critical)",
  "Major": "高 (Major)",
  "Minor": "中 (Minor)",
  "Informational": "資訊 (Informational)",
  "Unknown": "未指定 (Unknown)"
};

const CLASSTYPE_BILINGUAL = {
  "trojan-activity": "木馬活動 (trojan-activity)",
  "attempted-user": "嘗試取得使用者權限 (attempted-user)",
  "attempted-admin": "嘗試取得管理員權限 (attempted-admin)",
  "successful-admin": "成功取得管理員權限 (successful-admin)",
  "web-application-attack": "Web 應用攻擊 (web-application-attack)",
  "web-application-activity": "Web 存取活動 (web-application-activity)",
  "misc-attack": "網路攻擊特徵 (misc-attack)",
  "misc-activity": "異常網路活動 (misc-activity)",
  "policy-violation": "安全政策違規 (policy-violation)",
  "suspicious-filename-detect": "可疑惡意檔名 (suspicious-filename-detect)",
  "bad-unknown": "潛在惡意流量 (bad-unknown)",
  "default-login-attempt": "預設密碼登入 (default-login-attempt)",
  "network-scan": "網路埠號掃描 (network-scan)",
  "denial-of-service": "阻斷服務攻擊 (denial-of-service)",
  "shellcode-detect": "Shellcode 偵測 (shellcode-detect)",
  "successful-recon-limited": "情報探查成功-有限 (successful-recon-limited)",
  "successful-recon-largescale": "大規模情報探查 (successful-recon-largescale)",
  "not-suspicious": "非可疑流量 (not-suspicious)",
  "unsuccessful-user": "登入嘗試失敗 (unsuccessful-user)",
  "crypto-mining": "加密貨幣挖礦 (crypto-mining)",
  "credential-theft": "憑證竊取活動 (credential-theft)",
  "phishing": "網路釣魚活動 (phishing)",
  "command-and-control": "C2 指令控制 (command-and-control)",
  "targeted-activity": "定向攻擊滲透 (targeted-activity)"
};

function renderAllStats() {
  if (!globalInitData || !globalInitData.stats) return;
  const stats = globalInitData.stats;

  // Threat Actors
  const actorSearch = (document.getElementById("search-threat-actors")?.value || "").toLowerCase().trim();
  renderStatBars("threat-actor-stats-container", stats.threat_actors || {}, actorSearch, (name) => {
    switchTab("deployed-rules-tab");
    const el = document.getElementById("filter-threat-actor");
    if (el) el.value = name;
    fetchDeployedRules(true);
  });

  // Severities
  renderStatBars("severity-stats-container", stats.severities || {}, "", (name) => {
    switchTab("deployed-rules-tab");
    const el = document.getElementById("filter-severity");
    if (el) el.value = name;
    fetchDeployedRules(true);
  }, SEVERITY_BILINGUAL);

  // MITRE Tactics
  const mitreSearch = (document.getElementById("search-mitre-tactics")?.value || "").toLowerCase().trim();
  renderStatBars("mitre-tactic-stats-container", stats.mitre_tactics || {}, mitreSearch, (name) => {
    switchTab("deployed-rules-tab");
    const el = document.getElementById("filter-mitre-tactic");
    if (el) el.value = name;
    fetchDeployedRules(true);
  }, TACTIC_BILINGUAL);

  // CVE Years
  const cveSearch = (document.getElementById("search-cve-years")?.value || "").toLowerCase().trim();
  renderStatBars("cve-year-stats-container", stats.cve_years || {}, cveSearch, (year) => {
    switchTab("deployed-rules-tab");
    const el = document.getElementById("filter-cve-year");
    if (el) el.value = year;
    fetchDeployedRules(true);
  });
}

function renderStatBars(containerId, dict, searchFilter, onClickCallback, labelMap = null) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const entries = Object.entries(dict || {}).filter(([k, v]) => {
    if (!k || k === "unknown") return false;
    const label = (labelMap && labelMap[k]) ? labelMap[k] : k;
    if (searchFilter && !k.toLowerCase().includes(searchFilter) && !label.toLowerCase().includes(searchFilter)) return false;
    return true;
  });

  entries.sort((a, b) => b[1] - a[1]);

  if (entries.length === 0) {
    container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 1.5rem;">無符合資料</div>';
    return;
  }

  const maxVal = entries[0][1] || 1;
  let html = "";
  entries.forEach(([key, count]) => {
    const percent = Math.round((count / maxVal) * 100);
    const displayLabel = (labelMap && labelMap[key]) ? labelMap[key] : key;
    html += `
      <div style="cursor: pointer; display: flex; flex-direction: column; gap: 0.3rem;" onclick='(${onClickCallback.toString()})("${key.replace(/"/g, "&quot;")}")'>
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
          <span style="color: var(--text-primary); text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 75%;" title="${escapeHtml(displayLabel)}">${escapeHtml(displayLabel)}</span>
          <span style="color: var(--accent-cyan); font-weight: 600;">${count.toLocaleString()}</span>
        </div>
        <div style="width: 100%; height: 6px; background: rgba(255, 255, 255, 0.05); border-radius: 3px; overflow: hidden;">
          <div style="width: ${percent}%; height: 100%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-purple)); border-radius: 3px;"></div>
        </div>
      </div>
    `;
  });
  container.innerHTML = html;
}

function populateFacetsDropdowns(facets) {
  if (!facets) return;

  const fillSelect = (id, list, placeholder, labelMap = null) => {
    const select = document.getElementById(id);
    if (!select) return;
    const curr = select.value;
    select.innerHTML = `<option value="">${placeholder}</option>`;
    (list || []).forEach(val => {
      if (!val || val === "unknown") return;
      const opt = document.createElement("option");
      opt.value = val;
      opt.textContent = (labelMap && labelMap[val]) ? labelMap[val] : val;
      if (val === curr) opt.selected = true;
      select.appendChild(opt);
    });
  };

  fillSelect("filter-dataset", facets.datasets || facets.dataset, "所有規則集 (All Datasets)");
  fillSelect("filter-threat-actor", facets.threat_actors || facets.threat_actor, "所有威脅群組 (All Threat Actors)");
  fillSelect("filter-classtype", facets.classtypes || facets.classtype, "所有分類 (All Classtypes)", CLASSTYPE_BILINGUAL);
  fillSelect("filter-affected-product", facets.affected_products || facets.affected_product, "受影響產品 (Product)");
  fillSelect("filter-attack-target", facets.attack_targets || facets.attack_target, "攻擊目標 (Target)");
  fillSelect("filter-confidence", facets.confidences || facets.confidence, "可信度 (Confidence)");
  fillSelect("filter-severity", facets.severities || facets.signature_severity, "危害等級 (Severity)", SEVERITY_BILINGUAL);
  fillSelect("filter-mitre-tactic", facets.mitre_tactics || facets.mitre_tactic, "MITRE 戰術 (Tactic)", TACTIC_BILINGUAL);
  fillSelect("filter-cve-year", facets.cve_years || facets.cve_year, "CVE 年份 (Year)");
}

async function triggerPipeline() {
  if (!confirm("確定要立即觸發 ET Pro 規則下載與分析流程嗎？")) return;
  const btn = document.getElementById("btn-trigger-pipeline");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> 啟動中...';
  }

  try {
    const res = await apiFetch("/api/trigger", { method: "POST" });
    alert(res.message || "已成功觸發背景同步工作！");
    setTimeout(fetchStatus, 1500);
  } catch (e) {
    alert("觸發失敗: " + e.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-play"></i> 立即執行同步與下載';
    }
  }
}

// -------------------------------------------------------------
// SURICATA SYNTAX HIGHLIGHTER (VS Code Suricata Highlight Match)
// -------------------------------------------------------------
function highlightSuricataRule(rawRule) {
  if (!rawRule) return "";
  let str = String(rawRule).trim();
  
  // 1. Comment prefix check (e.g. # [VALIDATION FAILED - ...])
  let prefix = "";
  const commentMatch = str.match(/^(#\s*(?:\[[^\]]+\])?\s*)(.*)$/);
  if (commentMatch) {
    prefix = `<span class="suri-comment">${escapeHtml(commentMatch[1])}</span>`;
    str = commentMatch[2];
  }

  // 2. Separate Header and Options
  const openParenIdx = str.indexOf("(");
  if (openParenIdx === -1) {
    return prefix + highlightHeader(str);
  }

  const headerPart = str.slice(0, openParenIdx);
  const optionsPart = str.slice(openParenIdx);

  return prefix + highlightHeader(headerPart) + highlightOptions(optionsPart);
}

function highlightHeader(header) {
  return header.replace(/(\S+)/g, (token) => {
    // Direction operator
    if (token === "->" || token === "<>") {
      return `<span class="suri-keyword">${escapeHtml(token)}</span>`;
    }
    // Variables: $HOME_NET, $EXTERNAL_NET, $HTTP_PORTS, etc.
    if (token.startsWith("$")) {
      return `<span class="suri-variable">${escapeHtml(token)}</span>`;
    }
    // Action keywords
    if (/^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)$/i.test(token)) {
      return `<span class="suri-keyword">${escapeHtml(token)}</span>`;
    }
    // Protocol keywords
    if (/^(tcp|udp|icmp|ip|http|ftp|tls|smb|dns|ssh|smtp|dcerpc|dhcp|nfs|ike|krb5|snmp|tftp|rdp|modbus|enip|dnp3|cip)$/i.test(token)) {
      return `<span class="suri-keyword">${escapeHtml(token)}</span>`;
    }
    // 'any' port or address
    if (token.toLowerCase() === "any") {
      return `<span class="suri-value">${escapeHtml(token)}</span>`;
    }
    // Specific port numbers or IP ranges
    return `<span class="suri-number">${escapeHtml(token)}</span>`;
  });
}

function highlightOptions(options) {
  let out = '<span class="suri-punct">(</span>';
  let inner = options.slice(1);
  if (inner.endsWith(")")) inner = inner.slice(0, -1);

  // Match: option_key: option_val; OR flag;
  const optRegex = /([\s]*)([A-Za-z0-9_.-]+)(?:(\s*:\s*)("(?:\\"|[^"])*"|[^;]+))?([\s]*;)?/g;
  let lastIndex = 0;
  let match;

  while ((match = optRegex.exec(inner)) !== null) {
    if (match.index > lastIndex) {
      out += escapeHtml(inner.slice(lastIndex, match.index));
    }
    lastIndex = optRegex.lastIndex;

    const [full, leadingSpace, optKey, colonAndSpace, optVal, semicolonAndSpace] = match;

    out += escapeHtml(leadingSpace || "");
    // Option Key (Coral Red)
    out += `<span class="suri-keyword">${escapeHtml(optKey)}</span>`;

    if (colonAndSpace) {
      out += `<span class="suri-punct">${escapeHtml(colonAndSpace)}</span>`;
    }

    if (optVal !== undefined) {
      const valTrimmed = optVal.trim();
      if (valTrimmed.startsWith('"') && valTrimmed.endsWith('"')) {
        // Quoted string (Bright Sky Blue / Cyan)
        out += `<span class="suri-string">${escapeHtml(optVal)}</span>`;
      } else if (/^\d+$/.test(valTrimmed)) {
        // Number -> Cyan/Number
        out += `<span class="suri-number">${escapeHtml(optVal)}</span>`;
      } else {
        // Unquoted value (Light Gray)
        out += `<span class="suri-value">${escapeHtml(optVal)}</span>`;
      }
    }

    if (semicolonAndSpace) {
      out += `<span class="suri-punct">${escapeHtml(semicolonAndSpace)}</span>`;
    }

    if (match[0].length === 0) {
      optRegex.lastIndex++;
    }
  }

  if (lastIndex < inner.length) {
    out += escapeHtml(inner.slice(lastIndex));
  }

  out += '<span class="suri-punct">)</span>';
  return out;
}

// -------------------------------------------------------------
// DISABLED RULES TAB
// -------------------------------------------------------------
async function fetchDisabledRules() {
  try {
    const res = await apiFetch("/api/rules/disabled");
    allDisabledRules = Array.isArray(res) ? res : (res.rules || []);
    populateReasonFilter(allDisabledRules);
    filterDisabledRules(true);
  } catch (e) {
    console.error("fetchDisabledRules error:", e);
    const body = document.getElementById("disabled-rules-body");
    if (body) body.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--accent-red);">載入失敗: ${e.message}</td></tr>`;
  }
}

function populateReasonFilter(rules) {
  const filter = document.getElementById("rule-reason-filter");
  if (!filter) return;
  const curr = filter.value;
  const reasons = new Set();
  rules.forEach(r => {
    if (r.reason) reasons.add(r.reason);
  });
  filter.innerHTML = '<option value="">所有註解原因 (All Reasons)</option>';
  Array.from(reasons).sort().forEach(reason => {
    const opt = document.createElement("option");
    opt.value = reason;
    opt.textContent = reason;
    if (reason === curr) opt.selected = true;
    filter.appendChild(opt);
  });
}

function changePageSize() {
  const sel = document.getElementById("rule-pagesize");
  if (sel) disabledRulesLimit = parseInt(sel.value, 10) || 25;
  filterDisabledRules(true);
}

function filterDisabledRules(resetPage = false) {
  if (resetPage) disabledRulesPage = 1;

  const search = (document.getElementById("rule-search")?.value || "").toLowerCase().trim();
  const reason = document.getElementById("rule-reason-filter")?.value || "";

  const filtered = allDisabledRules.filter(r => {
    if (reason && r.reason !== reason) return false;
    if (search) {
      const matchSid = String(r.sid || "").includes(search);
      const matchContent = (r.content || "").toLowerCase().includes(search);
      const matchReason = (r.reason || "").toLowerCase().includes(search);
      if (!matchSid && !matchContent && !matchReason) return false;
    }
    return true;
  });

  const total = filtered.length;
  const startIdx = (disabledRulesPage - 1) * disabledRulesLimit;
  const endIdx = Math.min(startIdx + disabledRulesLimit, total);
  const pageRules = filtered.slice(startIdx, endIdx);

  const body = document.getElementById("disabled-rules-body");
  if (!body) return;

  if (pageRules.length === 0) {
    body.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">無符合已註解規則</td></tr>';
  } else {
    body.innerHTML = pageRules.map(r => `
      <tr>
        <td><span class="status-badge error" style="font-size: 0.75rem;">已註解</span></td>
        <td style="font-family: Consolas, monospace; font-weight: 600; color: var(--accent-cyan);">
          <a href="javascript:void(0)" onclick="openRuleDetailModal('${escapeHtml(String(r.sid))}')" style="color: var(--accent-cyan); text-decoration: none; cursor: pointer; display: inline-flex; align-items: center; gap: 4px;" title="點擊查看詳細特徵與語法">
            <i class="fa-solid fa-eye" style="font-size: 0.7rem; opacity: 0.7;"></i> ${escapeHtml(String(r.sid || "-"))}
          </a>
        </td>
        <td style="font-size: 0.8rem; color: var(--accent-orange); max-width: 260px; line-height: 1.4;">${escapeHtml(r.reason || r.timestamp || "Validation Failed")}</td>
        <td style="font-size: 0.8rem;">${escapeHtml(r.classtype || "-")}</td>
        <td><div class="suri-rule-container">${highlightSuricataRule(r.content || "")}</div></td>
      </tr>
    `).join("");
  }

  const pInfo = document.getElementById("pagination-info");
  if (pInfo) {
    pInfo.textContent = total > 0 ? `顯示第 ${startIdx + 1} 到 ${endIdx} 筆，共 ${total} 筆資料` : "顯示第 0 到 0 筆，共 0 筆資料";
  }

  renderPaginationControls("pagination-controls", disabledRulesPage, Math.ceil(total / disabledRulesLimit) || 1, (p) => {
    disabledRulesPage = p;
    filterDisabledRules(false);
  });
}

// -------------------------------------------------------------
// DEPLOYED RULES TAB
// -------------------------------------------------------------
function triggerDeployedRulesSearch() {
  clearTimeout(activeRulesDebounceTimer);
  activeRulesDebounceTimer = setTimeout(() => {
    fetchDeployedRules(true);
  }, 350);
}

async function fetchDeployedRules(resetPage = false) {
  if (resetPage) activeRulesPage = 1;

  const pageSizeEl = document.getElementById("deployed-rule-pagesize");
  if (pageSizeEl) activeRulesLimit = parseInt(pageSizeEl.value, 10) || 25;

  const params = new URLSearchParams({
    page: activeRulesPage,
    limit: activeRulesLimit,
    search: document.getElementById("deployed-rule-search")?.value || "",
    dataset: document.getElementById("filter-dataset")?.value || "",
    threat_actor: document.getElementById("filter-threat-actor")?.value || "",
    classtype: document.getElementById("filter-classtype")?.value || "",
    affected_product: document.getElementById("filter-affected-product")?.value || "",
    attack_target: document.getElementById("filter-attack-target")?.value || "",
    confidence: document.getElementById("filter-confidence")?.value || "",
    signature_severity: document.getElementById("filter-severity")?.value || "",
    mitre_tactic: document.getElementById("filter-mitre-tactic")?.value || "",
    cve_year: document.getElementById("filter-cve-year")?.value || "",
    cve: document.getElementById("filter-cve-input")?.value || ""
  });

  try {
    const res = await apiFetch(`/api/rules/active?${params.toString()}`);
    const rules = res.rules || [];
    const total = res.total || 0;

    const body = document.getElementById("deployed-rules-body");
    if (!body) return;

    if (rules.length === 0) {
      body.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">查無部署規則</td></tr>';
    } else {
      body.innerHTML = rules.map(r => `
        <tr>
          <td style="font-family: Consolas, monospace; font-weight: 600; color: var(--accent-cyan);">
            <a href="javascript:void(0)" onclick="openRuleDetailModal('${escapeHtml(String(r.sid))}')" style="color: var(--accent-cyan); text-decoration: none; cursor: pointer; display: inline-flex; align-items: center; gap: 4px;" title="點擊查看詳細特徵與複製 Suricata 語法">
              <i class="fa-solid fa-eye" style="font-size: 0.7rem; opacity: 0.7;"></i> ${escapeHtml(String(r.sid || "-"))}
            </a>
          </td>
          <td style="font-size: 0.8rem; color: var(--text-secondary);">${r.dataset || "-"}</td>
          <td style="font-size: 0.8rem;" title="${escapeHtml(CLASSTYPE_BILINGUAL[r.classtype] || r.classtype || "-")}">${escapeHtml(CLASSTYPE_BILINGUAL[r.classtype] || r.classtype || "-")}</td>
          <td style="font-size: 0.75rem;">
            ${r.threat_actor && r.threat_actor !== "unknown" ? `<span class="badge" style="background: rgba(139, 92, 246, 0.2); color: var(--accent-purple); margin-right: 4px;">${escapeHtml(r.threat_actor)}</span>` : ""}
            ${r.signature_severity && r.signature_severity !== "unknown" ? `<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: var(--accent-orange); margin-right: 4px;">${escapeHtml(SEVERITY_BILINGUAL[r.signature_severity] || r.signature_severity)}</span>` : ""}
            ${r.cve && r.cve !== "unknown" ? `<span class="badge" style="background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); margin-right: 4px;">${escapeHtml(r.cve)}</span>` : ""}
          </td>
          <td><div class="suri-rule-container">${highlightSuricataRule(r.content || "")}</div></td>
        </tr>
      `).join("");
    }

    const startIdx = total > 0 ? (activeRulesPage - 1) * activeRulesLimit + 1 : 0;
    const endIdx = Math.min(activeRulesPage * activeRulesLimit, total);
    const pInfo = document.getElementById("deployed-pagination-info");
    if (pInfo) {
      pInfo.textContent = total > 0 ? `顯示第 ${startIdx} 到 ${endIdx} 筆，共 ${total} 筆資料` : "顯示第 0 到 0 筆，共 0 筆資料";
    }

    renderPaginationControls("deployed-pagination-controls", activeRulesPage, res.total_pages || Math.ceil(total / activeRulesLimit) || 1, (p) => {
      activeRulesPage = p;
      fetchDeployedRules(false);
    });

  } catch (e) {
    console.error("fetchDeployedRules error:", e);
    const body = document.getElementById("deployed-rules-body");
    if (body) body.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--accent-red);">載入失敗: ${e.message}</td></tr>`;
  }
}

function clearCveFilter() {
  const inp = document.getElementById("filter-cve-input");
  if (inp) inp.value = "";
  const card = document.getElementById("cve-intel-card");
  if (card) card.style.display = "none";
  fetchDeployedRules(true);
}

function exportDeployedRulesCsv() {
  window.open("/api/rules/active/export", "_blank");
}

// -------------------------------------------------------------
// THREAT INTEL TAB
// -------------------------------------------------------------
async function fetchThreatActors() {
  try {
    const list = await apiFetch("/api/threat-actors");
    allThreatActors = Array.isArray(list) ? list : (list.actors || []);
    filterThreatActors();
  } catch (e) {
    console.error("fetchThreatActors error:", e);
    const c = document.getElementById("intel-list-container");
    if (c) c.innerHTML = `<div style="color: var(--accent-red); padding: 1.5rem;">載入失敗: ${e.message}</div>`;
  }
}

function getSeverityBadgeStyle(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "background: rgba(239, 68, 68, 0.18); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);";
  if (s === "major") return "background: rgba(249, 115, 22, 0.18); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3);";
  if (s === "minor") return "background: rgba(6, 182, 212, 0.18); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.3);";
  if (s === "informational") return "background: rgba(168, 85, 247, 0.18); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3);";
  return "background: rgba(255, 255, 255, 0.08); color: var(--text-muted); border: 1px solid var(--card-border);";
}

function filterThreatActors(autoSelect = true) {
  const search = (document.getElementById("intel-search")?.value || "").toLowerCase().trim();
  const filter = document.getElementById("intel-status-filter")?.value || "all";

  const container = document.getElementById("intel-list-container");
  if (!container) return;

  const filtered = allThreatActors.filter(a => {
    const rc = a.rule_count !== undefined ? a.rule_count : (a.rules_count || 0);
    const isMon = a.is_monitored || rc > 0;
    if (filter === "monitored" && !isMon) return false;
    if (filter === "unmonitored" && isMon) return false;
    if (search) {
      const nameMatch = (a.name || "").toLowerCase().includes(search);
      const aliasMatch = (a.aliases || []).some(al => al.toLowerCase().includes(search));
      if (!nameMatch && !aliasMatch) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 2rem;">無符合威脅群組</div>';
    return;
  }

  // Auto-select first actor if none selected or if current selection is not in filtered list
  if (autoSelect && (!selectedActorId || !filtered.some(a => a.id === selectedActorId))) {
    selectedActorId = filtered[0].id;
    loadThreatActorDetail(selectedActorId);
  }

  container.innerHTML = filtered.map(a => {
    const count = a.rule_count !== undefined ? a.rule_count : (a.rules_count || 0);
    const isSel = a.id === selectedActorId;
    return `
    <div class="intel-item ${isSel ? "active" : ""}" style="padding: 0.75rem 1rem; background: ${isSel ? "rgba(6, 182, 212, 0.12)" : "rgba(255,255,255,0.03)"}; border: 1px solid ${isSel ? "var(--accent-cyan)" : "var(--card-border)"}; border-radius: 0.5rem; cursor: pointer; transition: all 0.15s ease;" onclick="selectThreatActor('${a.id}')">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <strong style="color: var(--text-primary); font-size: 0.95rem;">${escapeHtml(a.name)}</strong>
        <span class="badge" style="background: ${count > 0 ? "rgba(6, 182, 212, 0.2)" : "rgba(255,255,255,0.05)"}; color: ${count > 0 ? "var(--accent-cyan)" : "var(--text-muted)"}; font-weight: 600;">
          ${count.toLocaleString()} 條規則
        </span>
      </div>
      <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
        別名: ${(a.aliases || []).slice(0, 3).map(escapeHtml).join(", ") || "無"}
      </div>
    </div>
  `}).join("");
}

async function selectThreatActor(actorId) {
  selectedActorId = actorId;
  filterThreatActors(false);
  loadThreatActorDetail(actorId);
}

let currentIntelActor = null;

function setIntelDescLang(lang) {
  if (!currentIntelActor) return;
  const box = document.getElementById("intel-desc-box");
  const btnBi = document.getElementById("btn-lang-bilingual");
  const btnZh = document.getElementById("btn-lang-zh");
  const btnEn = document.getElementById("btn-lang-en");
  
  [btnBi, btnZh, btnEn].forEach(b => {
    if (b) {
      b.style.background = "transparent";
      b.style.color = "var(--text-secondary)";
      b.style.fontWeight = "normal";
    }
  });

  const activeBtn = lang === "zh" ? btnZh : (lang === "en" ? btnEn : btnBi);
  if (activeBtn) {
    activeBtn.style.background = "var(--accent-cyan)";
    activeBtn.style.color = "#000";
    activeBtn.style.fontWeight = "600";
  }

  if (!box) return;
  if (lang === "zh") {
    box.textContent = currentIntelActor.description_zh || currentIntelActor.description || "暫無繁體中文描述";
  } else if (lang === "en") {
    box.textContent = currentIntelActor.description_en || currentIntelActor.description || "No English description available.";
  } else {
    box.textContent = currentIntelActor.description || "暫無詳細描述";
  }
}

function scrollToIntelSection(sectionId) {
  const el = document.getElementById(sectionId);
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    el.style.transition = 'all 0.3s ease';
    el.style.boxShadow = '0 0 15px rgba(6, 182, 212, 0.4)';
    setTimeout(() => {
      el.style.boxShadow = 'none';
    }, 1500);
  }
}

// -------------------------------------------------------------
// THREAT INTELLIGENCE & RULE INTERACTION HELPERS
// -------------------------------------------------------------
let currentActorDirectRules = [];

function clearDeployedRuleFilters() {
  const filterIds = [
    'filter-dataset', 'filter-threat-actor', 'filter-classtype',
    'filter-affected-product', 'filter-attack-target', 'filter-confidence',
    'filter-severity', 'filter-mitre-tactic', 'filter-cve-year', 'filter-cve-input'
  ];
  filterIds.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
}

function jumpToRule(sid) {
  closeRuleDetailModal();
  switchTab('deployed-rules-tab');
  clearDeployedRuleFilters();

  const searchInput = document.getElementById('deployed-rule-search');
  if (searchInput) {
    searchInput.value = String(sid).trim();
  }

  fetchDeployedRules(true);

  setTimeout(() => {
    const tableContainer = document.querySelector('#deployed-rules-tab .card');
    if (tableContainer) {
      tableContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, 120);
}

function jumpToMitreTechnique(techId) {
  closeRuleDetailModal();
  switchTab('deployed-rules-tab');
  clearDeployedRuleFilters();

  const searchInput = document.getElementById('deployed-rule-search');
  if (searchInput) {
    searchInput.value = techId;
  }

  fetchDeployedRules(true);

  setTimeout(() => {
    const tableContainer = document.querySelector('#deployed-rules-tab .card');
    if (tableContainer) {
      tableContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, 120);
}

function searchSoftwareInRules(softwareName) {
  closeRuleDetailModal();
  const cleanName = softwareName.replace(/\[.*?\]/g, '').trim();
  switchTab('deployed-rules-tab');
  clearDeployedRuleFilters();

  const searchInput = document.getElementById('deployed-rule-search');
  if (searchInput) {
    searchInput.value = cleanName;
  }

  fetchDeployedRules(true);

  setTimeout(() => {
    const tableContainer = document.querySelector('#deployed-rules-tab .card');
    if (tableContainer) {
      tableContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, 120);
}

function ensureRuleDetailModal() {
  if (document.getElementById("rule-detail-modal-backdrop")) return;
  const modalHtml = `
    <div id="rule-detail-modal-backdrop" onclick="if(event.target === this) closeRuleDetailModal()" style="position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); backdrop-filter: blur(8px); z-index: 99999; display: none; align-items: center; justify-content: center; padding: 1.5rem; opacity: 0; transition: opacity 0.2s ease;">
      <div id="rule-detail-modal-content" style="background: #111827; border: 1px solid var(--card-border); border-radius: 0.75rem; width: 100%; max-width: 820px; max-height: 90vh; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.9), 0 0 30px rgba(6, 182, 212, 0.2); transform: scale(0.96); transition: transform 0.2s ease;">
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem; border-bottom: 1px solid var(--card-border); background: rgba(255,255,255,0.02);">
          <div style="display: flex; align-items: center; gap: 0.6rem;">
            <i class="fa-solid fa-shield-halved" style="color: var(--accent-cyan); font-size: 1.1rem;"></i>
            <h3 id="modal-rule-title" style="margin: 0; font-size: 1.1rem; color: var(--text-primary); font-weight: 600;">規則特徵詳情</h3>
          </div>
          <button onclick="closeRuleDetailModal()" style="background: transparent; border: none; color: var(--text-muted); font-size: 1.2rem; cursor: pointer; padding: 0.25rem 0.5rem; border-radius: 0.25rem; transition: all 0.2s ease;" onmouseover="this.style.color='#fff'" onmouseout="this.style.color='var(--text-muted)'" title="關閉 (ESC)">
            <i class="fa-solid fa-xmark"></i>
          </button>
        </div>
        <div id="modal-rule-body" style="padding: 1.25rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1.1rem;">
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 0.75rem; padding: 0.85rem 1.25rem; border-top: 1px solid var(--card-border); background: rgba(0,0,0,0.3);">
          <button id="modal-btn-jump" class="btn btn-primary btn-sm" style="display: inline-flex; align-items: center; gap: 0.4rem;">
            <i class="fa-solid fa-arrow-up-right-from-square"></i> 至已部署規則庫查看
          </button>
          <button onclick="closeRuleDetailModal()" class="btn btn-secondary btn-sm">關閉</button>
        </div>
      </div>
    </div>
  `;
  document.body.insertAdjacentHTML("beforeend", modalHtml);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeRuleDetailModal();
  });
}

function closeRuleDetailModal() {
  const backdrop = document.getElementById("rule-detail-modal-backdrop");
  const modal = document.getElementById("rule-detail-modal-content");
  if (!backdrop) return;
  backdrop.style.opacity = "0";
  if (modal) modal.style.transform = "scale(0.96)";
  setTimeout(() => {
    backdrop.style.display = "none";
  }, 200);
}

function copyRuleToClipboard(btnEl) {
  const codeBlock = document.getElementById("raw-rule-code-block");
  if (!codeBlock) return;
  const text = codeBlock.textContent || "";
  navigator.clipboard.writeText(text).then(() => {
    const orig = btnEl.innerHTML;
    btnEl.innerHTML = '<i class="fa-solid fa-check"></i> 已複製!';
    btnEl.style.background = "rgba(16, 185, 129, 0.3)";
    btnEl.style.color = "var(--accent-green)";
    setTimeout(() => {
      btnEl.innerHTML = orig;
      btnEl.style.background = "rgba(6, 182, 212, 0.2)";
      btnEl.style.color = "var(--accent-cyan)";
    }, 1800);
  }).catch(err => {
    console.error("Clipboard copy failed:", err);
    alert("複製失敗，請手動選取文字複製");
  });
}

function openRuleDetailModal(sid, fallbackData = null) {
  ensureRuleDetailModal();
  const backdrop = document.getElementById("rule-detail-modal-backdrop");
  const modal = document.getElementById("rule-detail-modal-content");
  const body = document.getElementById("modal-rule-body");
  const title = document.getElementById("modal-rule-title");
  const jumpBtn = document.getElementById("modal-btn-jump");

  title.innerHTML = `<span style="font-family: monospace; color: var(--accent-cyan);">SID: ${escapeHtml(String(sid))}</span> 規則特徵詳情`;
  body.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 2.5rem;"><i class="fa-solid fa-spinner fa-spin fa-2x"></i><p style="margin-top: 0.6rem;">正在讀取規則詳細內容...</p></div>';

  jumpBtn.onclick = () => {
    closeRuleDetailModal();
    jumpToRule(sid);
  };

  backdrop.style.display = "flex";
  requestAnimationFrame(() => {
    backdrop.style.opacity = "1";
    modal.style.transform = "scale(1)";
  });

  (async () => {
    let rule = null;
    if (fallbackData && fallbackData.content) {
      rule = fallbackData;
    } else if (currentIntelActor && currentIntelActor.direct_rules) {
      rule = currentIntelActor.direct_rules.find(r => String(r.sid) === String(sid));
    }
    if (!rule || !rule.content) {
      try {
        rule = await apiFetch(`/api/rules/detail/${sid}`);
      } catch (e) {
        console.warn("Direct rule detail API lookup failed, falling back to search:", e);
        try {
          const res = await apiFetch(`/api/rules/active?search=${sid}&limit=1`);
          if (res.rules && res.rules.length > 0) {
            rule = res.rules[0];
          }
        } catch (err) {
          body.innerHTML = `<div style="color: var(--accent-red); padding: 1rem;">無法載入規則資訊: ${escapeHtml(err.message)}</div>`;
          return;
        }
      }
    }

    if (!rule) {
      body.innerHTML = `<div style="color: var(--accent-red); padding: 1rem;">找不到 SID ${escapeHtml(String(sid))} 的規則資料</div>`;
      return;
    }

    const rawContent = rule.content || "";
    body.innerHTML = `
      <div>
        <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.35rem;"><i class="fa-solid fa-bullhorn"></i> 規則訊息 (MSG):</div>
        <div style="font-size: 1.05rem; font-weight: 600; color: var(--text-primary); line-height: 1.45; background: rgba(0,0,0,0.25); padding: 0.65rem 0.85rem; border-radius: 0.4rem; border: 1px solid var(--card-border);">${escapeHtml(rule.msg || "無描述")}</div>
      </div>

      <div style="display: flex; flex-wrap: wrap; gap: 0.5rem; padding: 0.75rem; background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); border-radius: 0.5rem;">
        <span class="badge" style="${getSeverityBadgeStyle(rule.signature_severity)}">嚴重性: ${escapeHtml(SEVERITY_BILINGUAL[rule.signature_severity] || rule.signature_severity || "Unknown")}</span>
        ${rule.classtype ? `<span class="badge" style="background: rgba(255,255,255,0.08); color: var(--text-secondary);">分類: ${escapeHtml(CLASSTYPE_BILINGUAL[rule.classtype] || rule.classtype)}</span>` : ""}
        ${rule.threat_actor && rule.threat_actor !== "unknown" ? `<span class="badge" style="background: rgba(139, 92, 246, 0.15); color: var(--accent-purple);"><i class="fa-solid fa-user-ninja"></i> ${escapeHtml(rule.threat_actor)}</span>` : ""}
        ${rule.mitre_technique_id && rule.mitre_technique_id !== "unknown" ? `<span class="badge" style="background: rgba(168, 85, 247, 0.15); color: var(--accent-purple);"><i class="fa-solid fa-crosshairs"></i> ${escapeHtml(rule.mitre_technique_id)}</span>` : ""}
        ${rule.cve && rule.cve !== "unknown" ? `<span class="badge" style="background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan);"><i class="fa-solid fa-bug"></i> ${escapeHtml(rule.cve)}</span>` : ""}
        ${rule.dataset ? `<span class="badge" style="background: rgba(255,255,255,0.05); color: var(--text-muted);"><i class="fa-solid fa-box"></i> ${escapeHtml(rule.dataset)}</span>` : ""}
      </div>

      <div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
          <span style="font-size: 0.82rem; color: var(--text-muted); font-weight: 600;"><i class="fa-solid fa-code"></i> Suricata 原始特徵語法 (Raw Rule)</span>
          <button id="btn-copy-raw-rule" class="btn btn-xs" style="background: rgba(6, 182, 212, 0.2); color: var(--accent-cyan); border: 1px solid rgba(6, 182, 212, 0.4); padding: 0.25rem 0.65rem; cursor: pointer; border-radius: 0.3rem;" onclick="copyRuleToClipboard(this)">
            <i class="fa-solid fa-copy"></i> 複製語法
          </button>
        </div>
        <div>
          <pre id="raw-rule-code-block" class="suri-rule-container" style="margin: 0; background: rgba(0, 0, 0, 0.65);">${highlightSuricataRule(rawContent)}</pre>
        </div>
      </div>
    `;
  })();
}

function renderDirectRulesRows(rules) {
  return rules.map(r => `
    <tr style="border-bottom: 1px solid rgba(255,255,255,0.04); transition: background 0.15s ease;" onmouseover="this.style.background='rgba(6, 182, 212, 0.04)'" onmouseout="this.style.background='transparent'">
      <td style="padding: 0.6rem 0.75rem; width: 110px;">
        <a href="javascript:void(0)" onclick="jumpToRule('${escapeHtml(String(r.sid))}')" style="font-family: Consolas, monospace; color: var(--accent-cyan); font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 0.35rem;" title="點擊直接跳轉至已部署規則庫篩選此 SID">
          <i class="fa-solid fa-arrow-up-right-from-square" style="font-size: 0.7rem; opacity: 0.8;"></i> ${escapeHtml(String(r.sid))}
        </a>
      </td>
      <td style="padding: 0.6rem 0.75rem; width: 110px;">
        <span class="badge" style="${getSeverityBadgeStyle(r.signature_severity)}">${escapeHtml(SEVERITY_BILINGUAL[r.signature_severity] || r.signature_severity || "Unknown")}</span>
      </td>
      <td style="padding: 0.6rem 0.75rem; color: var(--text-primary); cursor: pointer;" onclick="openRuleDetailModal('${escapeHtml(String(r.sid))}')" title="點擊查看完整 Suricata 語法與詳情">
        <span style="display: block; max-width: 480px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; transition: color 0.15s ease;" onmouseover="this.style.color='var(--accent-cyan)'" onmouseout="this.style.color='var(--text-primary)'">
          ${escapeHtml(r.msg)}
        </span>
      </td>
      <td style="padding: 0.6rem 0.75rem; width: 140px; text-align: right;">
        <div style="display: inline-flex; gap: 0.35rem;">
          <button class="btn btn-xs" onclick="openRuleDetailModal('${escapeHtml(String(r.sid))}')" style="background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); border: 1px solid rgba(6, 182, 212, 0.35); padding: 0.2rem 0.5rem; font-size: 0.75rem; border-radius: 0.25rem; cursor: pointer;" title="查看 Suricata 特徵內容與語法">
            <i class="fa-solid fa-eye"></i> 詳情
          </button>
          <button class="btn btn-xs" onclick="jumpToRule('${escapeHtml(String(r.sid))}')" style="background: rgba(139, 92, 246, 0.15); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.35); padding: 0.2rem 0.5rem; font-size: 0.75rem; border-radius: 0.25rem; cursor: pointer;" title="前往已部署規則庫篩選此規則">
            <i class="fa-solid fa-arrow-right"></i> 規則庫
          </button>
        </div>
      </td>
    </tr>
  `).join("");
}

function filterActorDirectRules(query) {
  const q = (query || "").toLowerCase().trim();
  const filtered = q
    ? currentActorDirectRules.filter(r => 
        String(r.sid).toLowerCase().includes(q) || 
        (r.msg && r.msg.toLowerCase().includes(q)) ||
        (r.classtype && r.classtype.toLowerCase().includes(q)) ||
        (r.signature_severity && r.signature_severity.toLowerCase().includes(q))
      )
    : currentActorDirectRules;

  const countBadge = document.getElementById("actor-direct-rules-count-badge");
  if (countBadge) {
    countBadge.textContent = q ? `符合 ${filtered.length} / 共 ${currentActorDirectRules.length} 條` : `共 ${currentActorDirectRules.length} 條規則`;
  }

  const tbody = document.getElementById("actor-direct-rules-tbody");
  if (!tbody) return;

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-muted); padding: 2rem;">查無符合「${escapeHtml(query)}」的規則</td></tr>`;
    return;
  }

  tbody.innerHTML = renderDirectRulesRows(filtered);
}

async function loadThreatActorDetail(actorId) {
  const detailContainer = document.getElementById("intel-detail-container");
  if (!detailContainer) return;

  detailContainer.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 4rem;"><i class="fa-solid fa-spinner fa-spin fa-2x"></i><p style="margin-top: 1rem;">正在載入情報詳情...</p></div>';

  try {
    const actor = await apiFetch(`/api/threat-actors/${actorId}`);
    currentIntelActor = actor;
    const directRules = actor.direct_rules || [];
    currentActorDirectRules = directRules;
    const techniques = actor.techniques || [];
    const software = actor.software || [];
    const ruleCount = directRules.length || actor.rule_count || actor.rules_count || 0;

    let directRulesHtml = "";
    if (directRules.length === 0) {
      directRulesHtml = '<div style="padding: 1.5rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">暫無直接以該組織名稱標記的 Suricata 規則</div>';
    } else {
      directRulesHtml = `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.6rem 0.75rem; background: rgba(255,255,255,0.02); border-bottom: 1px solid var(--card-border); gap: 0.75rem; flex-wrap: wrap;">
          <div style="position: relative; flex: 1; min-width: 200px;">
            <i class="fa-solid fa-magnifying-glass" style="position: absolute; left: 0.65rem; top: 50%; transform: translateY(-50%); font-size: 0.75rem; color: var(--text-muted);"></i>
            <input type="text" id="filter-actor-direct-rules" placeholder="在當前群組規則中搜尋 SID、MSG 關鍵字..." oninput="filterActorDirectRules(this.value)" style="width: 100%; padding: 0.35rem 0.5rem 0.35rem 1.9rem; background: rgba(0,0,0,0.3); border: 1px solid var(--card-border); border-radius: 0.35rem; color: var(--text-primary); font-size: 0.82rem;">
          </div>
          <div id="actor-direct-rules-count-badge" style="font-size: 0.8rem; color: var(--accent-cyan); font-weight: 500;">
            共 ${directRules.length.toLocaleString()} 條規則
          </div>
        </div>
        <div style="max-height: 440px; overflow-y: auto;">
          <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
            <thead>
              <tr style="border-bottom: 1px solid var(--card-border); background: rgba(255,255,255,0.02); text-align: left; position: sticky; top: 0; background: #161c2d; z-index: 2;">
                <th style="padding: 0.6rem 0.75rem; color: var(--text-secondary); width: 110px;">SID</th>
                <th style="padding: 0.6rem 0.75rem; color: var(--text-secondary); width: 110px;">嚴重性</th>
                <th style="padding: 0.6rem 0.75rem; color: var(--text-secondary);">規則訊息 (MSG) - 點擊查看詳情</th>
                <th style="padding: 0.6rem 0.75rem; color: var(--text-secondary); width: 140px; text-align: right;">操作</th>
              </tr>
            </thead>
            <tbody id="actor-direct-rules-tbody">
              ${renderDirectRulesRows(directRules)}
            </tbody>
          </table>
        </div>
      `;
    }

    let techniquesHtml = "";
    if (techniques.length > 0) {
      techniquesHtml = `
        <div id="intel-techniques-section" style="scroll-margin-top: 20px; border-radius: 0.5rem; transition: box-shadow 0.3s ease;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <h4 style="font-size: 0.95rem; color: var(--text-secondary); margin: 0;">
              <i class="fa-solid fa-crosshairs"></i> MITRE ATT&CK 技術涵蓋 (${techniques.length})
            </h4>
            <span style="font-size: 0.75rem; color: var(--text-muted);">(點擊任一技術標籤可直接前往規則庫篩選特徵)</span>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 0.4rem; max-height: 200px; overflow-y: auto; padding: 0.6rem; background: rgba(0,0,0,0.15); border: 1px solid var(--card-border); border-radius: 0.5rem;">
            ${techniques.map(t => `
              <span class="badge" style="background: rgba(168, 85, 247, 0.15); color: var(--accent-purple); display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.35rem 0.6rem; cursor: pointer; transition: all 0.2s ease;" onclick="jumpToMitreTechnique('${escapeHtml(t.id)}')" title="點擊前往已部署規則庫篩選此 ATT&CK 技術: ${escapeHtml(t.id)}" onmouseover="this.style.background='rgba(168, 85, 247, 0.3)'" onmouseout="this.style.background='rgba(168, 85, 247, 0.15)'">
                <strong>${escapeHtml(t.id)}</strong> ${escapeHtml(t.display_name || t.name || t.id)}
                ${t.rule_count ? `<span style="background: rgba(255,255,255,0.18); border-radius: 999px; padding: 0.1rem 0.4rem; font-size: 0.7rem; color: #fff;"><i class="fa-solid fa-arrow-right" style="font-size: 0.55rem;"></i> ${t.rule_count.toLocaleString()} 條</span>` : ""}
              </span>
            `).join("")}
          </div>
        </div>
      `;
    }

    let softwareHtml = "";
    if (software.length > 0) {
      softwareHtml = `
        <div id="intel-software-section" style="scroll-margin-top: 20px; border-radius: 0.5rem; transition: box-shadow 0.3s ease;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <h4 style="font-size: 0.95rem; color: var(--text-secondary); margin: 0;">
              <i class="fa-solid fa-virus"></i> 關聯惡意軟體 / 工具 (${software.length})
            </h4>
            <span style="font-size: 0.75rem; color: var(--text-muted);">(點擊任一軟體標籤可直接前往規則庫搜尋特徵)</span>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 0.4rem;">
            ${software.map(s => `
              <span class="badge" style="background: rgba(34, 197, 94, 0.15); color: var(--accent-green); padding: 0.35rem 0.6rem; cursor: pointer; transition: all 0.2s ease;" onclick="searchSoftwareInRules('${escapeHtml(s)}')" title="點擊前往已部署規則庫搜尋 ${escapeHtml(s)}" onmouseover="this.style.background='rgba(34, 197, 94, 0.3)'" onmouseout="this.style.background='rgba(34, 197, 94, 0.15)'">
                <i class="fa-solid fa-magnifying-glass" style="font-size: 0.65rem; opacity: 0.7; margin-right: 0.25rem;"></i>${escapeHtml(s)}
              </span>
            `).join("")}
          </div>
        </div>
      `;
    }

    detailContainer.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 1.25rem;">
        <!-- Header -->
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem; border-bottom: 1px solid var(--card-border); padding-bottom: 1rem;">
          <div>
            <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
              <h2 style="font-size: 1.6rem; font-weight: 700; color: var(--text-primary); margin: 0;">${escapeHtml(actor.name)}</h2>
              <span class="badge" style="background: rgba(6, 182, 212, 0.18); color: var(--accent-cyan); font-weight: 600; font-size: 0.85rem; padding: 0.35rem 0.75rem;">
                ${ruleCount.toLocaleString()} 條防禦規則
              </span>
            </div>
            <p style="color: var(--accent-purple); font-size: 0.85rem; margin-top: 0.35rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;">
              <span><i class="fa-solid fa-fingerprint"></i> ${escapeHtml(actor.id || "")}</span>
              ${actor.source ? `<span class="badge" style="background: rgba(168, 85, 247, 0.15); color: var(--accent-purple);">${escapeHtml(actor.source)}</span>` : ""}
              ${actor.country ? `<span class="badge" style="background: rgba(255, 255, 255, 0.08); color: var(--text-secondary);"><i class="fa-solid fa-globe"></i> ${escapeHtml(actor.country)}</span>` : ""}
            </p>
          </div>
          <div style="display: flex; gap: 0.5rem;">
            <button class="btn btn-primary btn-sm" onclick="switchTab('deployed-rules-tab'); clearDeployedRuleFilters(); const f = document.getElementById('filter-threat-actor'); if (f) { f.value = '${escapeHtml(actor.name)}'; } fetchDeployedRules(true);">
              <i class="fa-solid fa-shield-halved"></i> 檢視關聯已部署規則 (${ruleCount.toLocaleString()})
            </button>
          </div>
        </div>

        <!-- Quick Stat Cards (Interactive & Clickable) -->
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
          <div class="card stat-click-card" onclick="scrollToIntelSection('intel-direct-rules-section')" title="點擊跳至直接防禦規則列表" style="padding: 0.85rem 1rem; background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); cursor: pointer; transition: all 0.2s ease;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="font-size: 0.75rem; color: var(--text-muted);"><i class="fa-solid fa-bullseye"></i> 直接防禦規則</div>
              <span style="font-size: 0.7rem; color: var(--accent-cyan); opacity: 0.8;"><i class="fa-solid fa-arrow-down"></i> 查看下表明細</span>
            </div>
            <div style="font-size: 1.3rem; font-weight: 700; color: var(--accent-cyan); margin-top: 0.25rem;">
              ${directRules.length.toLocaleString()}
            </div>
          </div>
          <div class="card stat-click-card" onclick="scrollToIntelSection('intel-techniques-section')" title="點擊跳至 ATT&CK 技術涵蓋標籤" style="padding: 0.85rem 1rem; background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); cursor: pointer; transition: all 0.2s ease;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="font-size: 0.75rem; color: var(--text-muted);"><i class="fa-solid fa-crosshairs"></i> ATT&CK 技術</div>
              <span style="font-size: 0.7rem; color: var(--accent-purple); opacity: 0.8;"><i class="fa-solid fa-arrow-down"></i> 查看技術庫</span>
            </div>
            <div style="font-size: 1.3rem; font-weight: 700; color: var(--accent-purple); margin-top: 0.25rem;">
              ${techniques.length.toLocaleString()}
            </div>
          </div>
          <div class="card stat-click-card" onclick="scrollToIntelSection('intel-software-section')" title="點擊跳至關聯軟體 / 工具列表" style="padding: 0.85rem 1rem; background: rgba(255,255,255,0.02); border: 1px solid var(--card-border); cursor: pointer; transition: all 0.2s ease;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <div style="font-size: 0.75rem; color: var(--text-muted);"><i class="fa-solid fa-virus"></i> 關聯軟體 / 工具</div>
              <span style="font-size: 0.7rem; color: var(--accent-green); opacity: 0.8;"><i class="fa-solid fa-arrow-down"></i> 查看家族清單</span>
            </div>
            <div style="font-size: 1.3rem; font-weight: 700; color: var(--accent-green); margin-top: 0.25rem;">
              ${software.length.toLocaleString()}
            </div>
          </div>
        </div>

        <!-- Aliases Section -->
        <div>
          <h4 style="font-size: 0.95rem; color: var(--text-secondary); margin-bottom: 0.5rem;"><i class="fa-solid fa-tags"></i> 別名與代號 (Aliases)</h4>
          <div style="display: flex; flex-wrap: wrap; gap: 0.4rem;">
            ${(actor.aliases || []).map(al => `<span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-primary);">${escapeHtml(al)}</span>`).join("") || '<span style="color: var(--text-muted);">無</span>'}
          </div>
        </div>

        <!-- Description Section with Bilingual Toggle -->
        <div>
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 0.5rem;">
            <h4 style="font-size: 0.95rem; color: var(--text-secondary); margin: 0;">
              <i class="fa-solid fa-book-open"></i> 情報描述 (Description)
            </h4>
            <div style="display: inline-flex; gap: 0.25rem; background: rgba(0,0,0,0.3); padding: 0.2rem; border-radius: 0.4rem; border: 1px solid var(--card-border);">
              <button id="btn-lang-bilingual" class="btn btn-xs" style="padding: 0.2rem 0.6rem; font-size: 0.75rem; background: var(--accent-cyan); color: #000; font-weight: 600; border: none; border-radius: 0.25rem; cursor: pointer;" onclick="setIntelDescLang('bilingual')">中英對照</button>
              <button id="btn-lang-zh" class="btn btn-xs" style="padding: 0.2rem 0.6rem; font-size: 0.75rem; background: transparent; color: var(--text-secondary); border: none; border-radius: 0.25rem; cursor: pointer;" onclick="setIntelDescLang('zh')">繁體中文</button>
              <button id="btn-lang-en" class="btn btn-xs" style="padding: 0.2rem 0.6rem; font-size: 0.75rem; background: transparent; color: var(--text-secondary); border: none; border-radius: 0.25rem; cursor: pointer;" onclick="setIntelDescLang('en')">English</button>
            </div>
          </div>
          <p id="intel-desc-box" style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6; background: rgba(0,0,0,0.2); padding: 0.85rem 1.1rem; border-radius: 0.5rem; border: 1px solid var(--card-border); white-space: pre-line;">
            ${escapeHtml(actor.description || "暫無詳細描述")}
          </p>
        </div>

        <!-- Direct Rules Section -->
        <div id="intel-direct-rules-section" style="scroll-margin-top: 20px; border-radius: 0.5rem; transition: box-shadow 0.3s ease;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <h4 style="font-size: 0.95rem; color: var(--text-secondary); margin: 0;">
              <i class="fa-solid fa-list-check"></i> 關聯直接防禦規則 (Direct Protection Rules)
            </h4>
            <span style="font-size: 0.8rem; color: var(--text-muted);">共 ${directRules.length.toLocaleString()} 條 (點擊 SID 或規則可跳轉或查看詳細語法)</span>
          </div>
          <div style="border: 1px solid var(--card-border); border-radius: 0.5rem; overflow: hidden; background: rgba(0,0,0,0.2);">
            ${directRulesHtml}
          </div>
        </div>

        <!-- Techniques -->
        ${techniquesHtml}

        <!-- Software -->
        ${softwareHtml}
      </div>
    `;
  } catch (e) {
    detailContainer.innerHTML = `<div style="color: var(--accent-red); padding: 2rem;">載入失敗: ${escapeHtml(e.message)}</div>`;
  }
}

// -------------------------------------------------------------
// CTI BLOCKLIST TAB
// -------------------------------------------------------------
let ctiFiltersLoaded = false;

async function initCtiFilters() {
  if (ctiFiltersLoaded) return;
  try {
    const res = await apiFetch("/api/cti/filter_options");
    if (!res) return;

    const fillSelect = (id, options, defaultLabel) => {
      const el = document.getElementById(id);
      if (!el) return;
      const curVal = el.value;
      let html = `<option value="">全部${defaultLabel ? " " + defaultLabel : ""}</option>`;
      if (Array.isArray(options)) {
        options.filter(o => o && o !== "unknown" && o !== "None").forEach(o => {
          html += `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`;
        });
      }
      el.innerHTML = html;
      el.value = curVal;
    };

    if (res.types) fillSelect("cti-filter-type", res.types, "類型");
    if (res.sources) fillSelect("cti-filter-source", res.sources, "來源");
    if (res.threat_actors) fillSelect("cti-filter-actor", res.threat_actors, "威脅群組");
    if (res.malware_tags) fillSelect("cti-filter-malware", res.malware_tags, "惡意軟體");

    ctiFiltersLoaded = true;
  } catch (e) {
    console.error("initCtiFilters error:", e);
  }
}

async function fetchCtiStatus() {
  try {
    const data = await apiFetch("/api/cti/status");
    const tot = document.getElementById("cti-total-rules");
    if (tot) tot.textContent = (data.total_rules || 0).toLocaleString();
    const ipR = document.getElementById("cti-ip-rules");
    if (ipR) ipR.textContent = (data.ip_rules || data.total_ip_rules || 0).toLocaleString();
    const domR = document.getElementById("cti-domain-rules");
    if (domR) domR.textContent = (data.domain_rules || data.total_domain_rules || 0).toLocaleString();
    const syncT = document.getElementById("cti-sync-time");
    if (syncT) {
      const t = data.last_sync || data.sync_time;
      if (t) {
        try {
          syncT.textContent = new Date(t).toLocaleString();
        } catch (_) {
          syncT.textContent = t;
        }
      } else {
        syncT.textContent = "無";
      }
    }

    // Feeds container
    const feedsContainer = document.getElementById("cti-feeds-status-container");
    if (feedsContainer) {
      let feedList = [];
      if (Array.isArray(data.feed_list)) {
        feedList = data.feed_list;
      } else if (Array.isArray(data.feeds)) {
        feedList = data.feeds;
      } else if (data.feeds && typeof data.feeds === "object") {
        const feedNames = { "feodo": "Feodo Tracker", "urlhaus": "URLhaus", "et_compromised": "ET Compromised" };
        feedList = Object.entries(data.feeds).map(([name, f]) => ({
          name: feedNames[name] || name,
          enabled: f.enabled !== false,
          count: (f.ips_count || 0) + (f.domains_count || 0) || f.count || 0,
          status: f.status || "ready"
        }));
      }

      if (feedList.length === 0) {
        feedsContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem; padding: 1rem;">暫無情資來源資料</div>';
      } else {
        feedsContainer.innerHTML = feedList.map(f => `
          <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <strong style="color: var(--text-primary);">${f.name}</strong>
              <span class="status-badge ${f.enabled ? "running" : "idle"}">${f.enabled ? "已啟用" : "已停用"}</span>
            </div>
            <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem;">
              取得特徵數: <span style="color: var(--accent-cyan); font-weight: 600;">${(f.count || 0).toLocaleString()}</span>
            </div>
          </div>
        `).join("");
      }
    }
  } catch (e) {
    console.error("fetchCtiStatus error:", e);
  }
}

function onCtiSearchInput() {
  clearTimeout(ctiDebounceTimer);
  ctiDebounceTimer = setTimeout(() => {
    applyCtiFilters(true);
  }, 350);
}

function changeCtiPageSize() {
  const sel = document.getElementById("cti-pagesize");
  if (sel) ctiLimit = parseInt(sel.value, 10) || 25;
  applyCtiFilters(true);
}

function resetCtiFilters() {
  const s = document.getElementById("cti-search"); if (s) s.value = "";
  const t = document.getElementById("cti-filter-type"); if (t) t.value = "";
  const a = document.getElementById("cti-filter-actor"); if (a) a.value = "";
  const m = document.getElementById("cti-filter-malware"); if (m) m.value = "";
  const src = document.getElementById("cti-filter-source"); if (src) src.value = "";
  const st = document.getElementById("cti-filter-start"); if (st) st.value = "";
  const en = document.getElementById("cti-filter-end"); if (en) en.value = "";
  applyCtiFilters(true);
}

async function applyCtiFilters(resetPage = false) {
  if (resetPage) ctiPage = 1;

  const params = new URLSearchParams({
    page: ctiPage,
    limit: ctiLimit,
    search: document.getElementById("cti-search")?.value || "",
    type: document.getElementById("cti-filter-type")?.value || "",
    threat_actor: document.getElementById("cti-filter-actor")?.value || "",
    actor: document.getElementById("cti-filter-actor")?.value || "",
    malware_tag: document.getElementById("cti-filter-malware")?.value || "",
    malware: document.getElementById("cti-filter-malware")?.value || "",
    source: document.getElementById("cti-filter-source")?.value || "",
    start_date: document.getElementById("cti-filter-start")?.value || "",
    end_date: document.getElementById("cti-filter-end")?.value || ""
  });

  try {
    const res = await apiFetch(`/api/cti/iocs?${params.toString()}`);
    const iocs = res.items || res.iocs || [];
    const total = res.total || 0;

    const body = document.getElementById("cti-ioc-table-body");
    if (!body) return;

    if (iocs.length === 0) {
      body.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">無符合 IoC 清單</td></tr>';
    } else {
      body.innerHTML = iocs.map(ioc => {
        const typeStr = (ioc.type || "IP").toUpperCase();
        const typeBadgeStyle = typeStr === "IP" 
          ? "background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); border: 1px solid rgba(6, 182, 212, 0.3);"
          : "background: rgba(168, 85, 247, 0.15); color: var(--accent-purple); border: 1px solid rgba(168, 85, 247, 0.3);";

        const hasActor = ioc.threat_actor && ioc.threat_actor !== "unknown" && ioc.threat_actor !== "None";
        const hasMalware = ioc.malware_tag && ioc.malware_tag !== "unknown" && ioc.malware_tag !== "None";

        let dateDisplay = "-";
        const rawDate = ioc.added_date || ioc.updated_at;
        if (rawDate) {
          try {
            dateDisplay = new Date(rawDate).toLocaleString();
          } catch (_) {
            dateDisplay = rawDate;
          }
        }

        return `
          <tr>
            <td><span class="badge" style="${typeBadgeStyle} border-radius: 4px; padding: 2px 8px; font-size: 0.75rem; font-weight: 600;">${typeStr}</span></td>
            <td style="font-family: Consolas, monospace; font-weight: 600; color: var(--text-primary); font-size: 0.9rem;">${escapeHtml(ioc.value || "-")}</td>
            <td>${hasActor ? `<span class="badge" style="background: rgba(236, 72, 153, 0.15); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.3); border-radius: 4px; padding: 2px 6px; font-size: 0.75rem;">${escapeHtml(ioc.threat_actor)}</span>` : '<span style="color: var(--text-muted);">-</span>'}</td>
            <td>${hasMalware ? `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 4px; padding: 2px 6px; font-size: 0.75rem;">${escapeHtml(ioc.malware_tag)}</span>` : '<span style="color: var(--text-muted);">-</span>'}</td>
            <td style="color: var(--text-secondary); font-size: 0.85rem;"><i class="fa-solid fa-cloud-arrow-down" style="font-size: 0.75rem; margin-right: 4px; color: var(--text-muted);"></i>${escapeHtml(ioc.source || "-")}</td>
            <td style="color: var(--text-muted); font-size: 0.8rem;">${dateDisplay}</td>
          </tr>
        `;
      }).join("");
    }

    const startIdx = total > 0 ? (ctiPage - 1) * ctiLimit + 1 : 0;
    const endIdx = Math.min(ctiPage * ctiLimit, total);
    const pInfo = document.getElementById("cti-pagination-info");
    if (pInfo) {
      pInfo.textContent = total > 0 ? `顯示第 ${startIdx} 至 ${endIdx} 筆，共 ${total.toLocaleString()} 筆` : "顯示第 0 至 0 筆，共 0 筆";
    }

    renderPaginationControls("cti-pagination-controls", ctiPage, Math.ceil(total / ctiLimit) || 1, (p) => {
      ctiPage = p;
      applyCtiFilters(false);
    });

  } catch (e) {
    console.error("applyCtiFilters error:", e);
    const body = document.getElementById("cti-ioc-table-body");
    if (body) body.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-red);">載入失敗: ${e.message}</td></tr>`;
  }
}


async function syncCtiFeeds() {
  const btn = document.getElementById("cti-sync-btn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> 同步中...';
  }

  try {
    const res = await apiFetch("/api/cti/sync", { method: "POST" });
    alert(res.message || "CTI 情資同步已觸發！");
    setTimeout(() => {
      fetchCtiStatus();
      applyCtiFilters(true);
    }, 2000);
  } catch (e) {
    alert("同步失敗: " + e.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-arrows-rotate"></i> 立即同步 CTI 情資';
    }
  }
}

function exportCtiCsv() {
  window.open("/api/cti/export", "_blank");
}

// -------------------------------------------------------------
// ROLLBACK TAB
// -------------------------------------------------------------
async function fetchDeployments() {
  try {
    const res = await apiFetch("/api/deployments");
    const backups = res.backups || [];
    const body = document.getElementById("deployments-body");
    if (!body) return;

    if (backups.length === 0) {
      body.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">無歷史部署備份</td></tr>';
      return;
    }

    body.innerHTML = backups.map(b => `
      <tr>
        <td style="font-family: Consolas, monospace; font-weight: 600;">${b.filename}</td>
        <td><span class="status-badge idle">歸檔備份</span></td>
        <td>${(b.size / 1024 / 1024).toFixed(2)} MB</td>
        <td>${new Date(b.mtime * 1000).toLocaleString()}</td>
        <td style="color: var(--text-muted);">歷史封存檔案</td>
        <td style="text-align: center;">
          <button class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.8rem;" onclick="rollbackDeployment('${b.filename}')">
            <i class="fa-solid fa-rotate-left"></i> 回滾此版本
          </button>
        </td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("fetchDeployments error:", e);
  }
}

async function rollbackDeployment(filename) {
  if (!confirm(`確定要回滾至 ${filename} 嗎？此動作將覆蓋當前部署規則。`)) return;
  try {
    await apiFetch("/api/deployments/rollback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename })
    });
    alert("回滾完成！已恢復為指定歷史規則。");
    fetchStatus();
    fetchDeployments();
  } catch (e) {
    alert("回滾失敗: " + e.message);
  }
}

// -------------------------------------------------------------
// LOGS TAB
// -------------------------------------------------------------
async function fetchLogs() {
  try {
    const res = await fetch("/api/logs");
    let lines = [];
    if (res.ok) {
      const ct = res.headers.get("content-type") || "";
      if (ct.includes("application/json")) {
        const data = await res.json();
        lines = data.lines || [];
      } else {
        const text = await res.text();
        lines = text.split("\n").filter(Boolean);
      }
    }
    const body = document.getElementById("console-body");
    if (!body) return;
    body.innerHTML = lines.map(line => `<div>${escapeHtml(line)}</div>`).join("");
    body.scrollTop = body.scrollHeight;
    const statusText = document.getElementById("log-status-text");
    if (statusText) statusText.textContent = `共 ${lines.length} 行`;
  } catch (e) {
    console.error("fetchLogs error:", e);
  }
}

function toggleLogAutoRefresh() {
  const chk = document.getElementById("auto-refresh-logs");
  if (chk && chk.checked) {
    startLogStream();
  } else {
    stopLogStream();
  }
}

function startLogStream() {
  if (logEventSource) return;
  const statusText = document.getElementById("log-status-text");
  if (statusText) statusText.textContent = "即時串流連線中...";

  try {
    logEventSource = new EventSource("/api/stream");
    logEventSource.onmessage = (event) => {
      const body = document.getElementById("console-body");
      if (body) {
        const div = document.createElement("div");
        div.textContent = event.data;
        body.appendChild(div);
        body.scrollTop = body.scrollHeight;
      }
    };
    logEventSource.onerror = () => {
      stopLogStream();
    };
  } catch (e) {
    console.error("SSE failed:", e);
  }
}

function stopLogStream() {
  if (logEventSource) {
    logEventSource.close();
    logEventSource = null;
  }
  const statusText = document.getElementById("log-status-text");
  if (statusText) statusText.textContent = "已暫停即時串流";
}

// -------------------------------------------------------------
// SURICATA CONFIG TAB
// -------------------------------------------------------------
async function fetchSuricataYaml() {
  try {
    const data = await apiFetch("/api/system/suricata-yaml");
    const pathEl = document.getElementById("suricata-yaml-path");
    if (pathEl) pathEl.textContent = `檔案路徑: ${data.path || "-"}`;

    const editorEl = document.getElementById("suricata-yaml-editor");
    if (editorEl) editorEl.value = data.content || "";
  } catch (e) {
    alert("載入 Suricata 設定檔失敗: " + e.message);
  }
}

async function saveSuricataYaml() {
  const editorEl = document.getElementById("suricata-yaml-editor");
  if (!editorEl) return;
  const content = editorEl.value;

  try {
    await apiFetch("/api/system/suricata-yaml", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content })
    });
    alert("Suricata 設定檔已儲存成功 (自動備份已建立)！");
  } catch (e) {
    alert("儲存失敗: " + e.message);
  }
}

async function testSuricataYaml() {
  const outputEl = document.getElementById("suricata-test-output");
  if (outputEl) outputEl.textContent = "正在執行 Suricata 語法測試 (-T)...";

  try {
    const res = await apiFetch("/api/system/suricata-test", { method: "POST" });
    if (outputEl) {
      outputEl.textContent = res.output || (res.success ? "語法測試通過！" : "語法測試失敗。");
      outputEl.style.color = res.success ? "var(--accent-green)" : "var(--accent-red)";
    }
  } catch (e) {
    if (outputEl) {
      outputEl.textContent = "測試執行失敗: " + e.message;
      outputEl.style.color = "var(--accent-red)";
    }
  }
}

// -------------------------------------------------------------
// CONFIG TAB (Threat Intel Overrides)
// -------------------------------------------------------------
let currentConfigData = { actor_mappings: {}, software_denylist: [] };

async function fetchConfig() {
  try {
    const data = await apiFetch("/api/config");
    currentConfigData = data;
    renderConfigUI();
  } catch (e) {
    console.error("fetchConfig error:", e);
  }
}

function renderConfigUI() {
  // Render Actor Mappings
  const list = document.getElementById("actor-mappings-list");
  if (list) {
    const entries = Object.entries(currentConfigData.actor_mappings || {});
    if (entries.length === 0) {
      list.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">尚未設定任何別名對應</div>';
    } else {
      list.innerHTML = entries.map(([group, aliases]) => `
        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 0.75rem 1rem; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <strong style="color: var(--accent-cyan);">${group}</strong>
            <span style="color: var(--text-muted); margin-left: 0.5rem;">[${(aliases || []).join(", ")}]</span>
          </div>
          <button class="btn btn-secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;" onclick="removeActorGroup('${group}')">
            <i class="fa-solid fa-trash"></i>
          </button>
        </div>
      `).join("");
    }
  }

  // Render Software Tags
  const tags = document.getElementById("software-tags");
  if (tags) {
    const list = currentConfigData.software_denylist || [];
    if (list.length === 0) {
      tags.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">尚未設定黑名單標籤</div>';
    } else {
      tags.innerHTML = list.map(item => `
        <span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171; padding: 0.4rem 0.8rem; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.5rem;">
          ${item}
          <i class="fa-solid fa-xmark" style="cursor: pointer;" onclick="removeSoftwareTag('${item}')"></i>
        </span>
      `).join("");
    }
  }
}

function addActorMapping() {
  const grpInput = document.getElementById("actor-input-group");
  const aliasInput = document.getElementById("actor-input-alias");
  const group = grpInput?.value.trim();
  const alias = aliasInput?.value.trim();
  if (!group || !alias) {
    alert("請輸入群組名稱與別名！");
    return;
  }
  if (!currentConfigData.actor_mappings) currentConfigData.actor_mappings = {};
  if (!currentConfigData.actor_mappings[group]) currentConfigData.actor_mappings[group] = [];
  if (!currentConfigData.actor_mappings[group].includes(alias)) {
    currentConfigData.actor_mappings[group].push(alias);
  }
  grpInput.value = "";
  aliasInput.value = "";
  renderConfigUI();
}

function removeActorGroup(group) {
  if (currentConfigData.actor_mappings && currentConfigData.actor_mappings[group]) {
    delete currentConfigData.actor_mappings[group];
    renderConfigUI();
  }
}

function addSoftwareTag() {
  const inp = document.getElementById("software-tag-input");
  const val = inp?.value.trim();
  if (!val) return;
  if (!currentConfigData.software_denylist) currentConfigData.software_denylist = [];
  if (!currentConfigData.software_denylist.includes(val)) {
    currentConfigData.software_denylist.push(val);
  }
  inp.value = "";
  renderConfigUI();
}

function removeSoftwareTag(tag) {
  if (currentConfigData.software_denylist) {
    currentConfigData.software_denylist = currentConfigData.software_denylist.filter(x => x !== tag);
    renderConfigUI();
  }
}

async function saveConfig() {
  try {
    await apiFetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentConfigData)
    });
    alert("設定檔已成功儲存！");
  } catch (e) {
    alert("儲存設定失敗: " + e.message);
  }
}

// -------------------------------------------------------------
// GEOIP TAB (Dark Theme SOC Flow & Threat Visualizer)
// -------------------------------------------------------------
function initGeoIPMap() {
  const container = document.getElementById("geoip-map");
  if (!container || typeof L === "undefined") return;

  if (geoipMap) {
    setTimeout(() => {
      if (geoipMap) geoipMap.invalidateSize();
    }, 150);
    return;
  }

  // Initialize with CartoDB Dark Matter tile layer
  geoipMap = L.map("geoip-map", {
    center: [23.5, 120.9],
    zoom: 3,
    minZoom: 2,
    maxZoom: 18,
    worldCopyJump: true
  });

  geoipTileLayer = L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
    subdomains: "abcd",
    maxZoom: 19
  }).addTo(geoipMap);

  geoipCurrentTheme = "dark";

  setTimeout(() => {
    if (geoipMap) geoipMap.invalidateSize();
  }, 200);
}

function toggleMapTheme() {
  if (!geoipMap) return;
  const btn = document.getElementById("map-theme-btn");
  if (geoipCurrentTheme === "dark") {
    geoipCurrentTheme = "light";
    if (geoipTileLayer) geoipMap.removeLayer(geoipTileLayer);
    geoipTileLayer = L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(geoipMap);
    if (btn) btn.innerHTML = '<i class="fa-solid fa-moon"></i> 深色圖資';
  } else {
    geoipCurrentTheme = "dark";
    if (geoipTileLayer) geoipMap.removeLayer(geoipTileLayer);
    geoipTileLayer = L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
      subdomains: "abcd",
      maxZoom: 19
    }).addTo(geoipMap);
    if (btn) btn.innerHTML = '<i class="fa-solid fa-circle-half-stroke"></i> 圖資切換';
  }
}

function resetGeoIPView() {
  if (geoipMap) {
    geoipMap.setView([20, 0], 2);
  }
}

function fitGeoIPBounds() {
  if (!geoipMap || geoipMarkers.length === 0) return;
  const bounds = [];
  geoipMarkers.forEach(m => {
    if (typeof m.getLatLng === "function") {
      bounds.push(m.getLatLng());
    }
  });
  if (bounds.length > 0) {
    geoipMap.fitBounds(bounds, { padding: [50, 50], maxZoom: 8 });
  }
}

function clearGeoIPMap() {
  geoipMarkers.forEach(m => m.remove());
  geoipMarkers = [];
  geoipLines.forEach(l => l.remove());
  geoipLines = [];

  const statNodes = document.getElementById("geoip-stat-nodes");
  const statCountries = document.getElementById("geoip-stat-countries");
  const statIsp = document.getElementById("geoip-stat-isp");
  const countryCount = document.getElementById("geoip-country-count");
  const countryList = document.getElementById("geoip-country-list");

  if (statNodes) statNodes.textContent = "0";
  if (statCountries) statCountries.textContent = "0";
  if (statIsp) {
    statIsp.textContent = "-";
    statIsp.title = "";
  }
  if (countryCount) countryCount.textContent = "共 0 國";
  if (countryList) {
    countryList.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 2rem 0;">尚未載入節點資料</div>';
  }
  resetGeoIPLegend();
}

const FLOW_DEST_COLORS = [
  { name: "rose", hex: "#f43f5e", label: "玫瑰紅" },
  { name: "amber", hex: "#f59e0b", label: "琥珀金" },
  { name: "emerald", hex: "#10b981", label: "翡翠綠" },
  { name: "purple", hex: "#a855f7", label: "霓虹紫" },
  { name: "blue", hex: "#3b82f6", label: "科技藍" },
  { name: "pink", hex: "#ec4899", label: "桃粉紅" },
  { name: "orange", hex: "#f97316", label: "烈焰橘" },
  { name: "teal", hex: "#14b8a6", label: "碧藍綠" },
  { name: "indigo", hex: "#6366f1", label: "極光靛" }
];

function resetGeoIPLegend() {
  const legend = document.getElementById("geoip-legend");
  if (!legend) return;
  legend.innerHTML = `
    <div style="display: flex; align-items: center; gap: 0.4rem;">
      <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #06b6d4; box-shadow: 0 0 6px #06b6d4;"></span>
      <span style="color: var(--text-secondary);">來源節點 / 一般 IP</span>
    </div>
    <div style="display: flex; align-items: center; gap: 0.4rem;">
      <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #ef4444; box-shadow: 0 0 6px #ef4444;"></span>
      <span style="color: var(--text-secondary);">惡意 / 威脅目標 IP</span>
    </div>
    <div style="display: flex; align-items: center; gap: 0.4rem;">
      <span style="display: inline-block; width: 16px; height: 2px; background: #06b6d4;"></span>
      <span style="color: var(--text-secondary);">跨國流量流向</span>
    </div>
  `;
}

function updateFlowGeoIPLegend(validDstNodes) {
  const legend = document.getElementById("geoip-legend");
  if (!legend) return;

  let itemsHtml = `
    <div style="display: flex; align-items: center; gap: 0.4rem; padding-right: 0.5rem; border-right: 1px solid rgba(255,255,255,0.15);">
      <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #06b6d4; box-shadow: 0 0 6px #06b6d4;"></span>
      <span style="color: var(--text-secondary); font-weight: 500;">來源端 (Source)</span>
    </div>
  `;

  validDstNodes.forEach((dst, i) => {
    const col = dst.color || FLOW_DEST_COLORS[i % FLOW_DEST_COLORS.length];
    itemsHtml += `
      <div style="display: flex; align-items: center; gap: 0.4rem;" title="目的端: ${escapeHtml(dst.ip)} (${escapeHtml(dst.data?.country || '-')})">
        <span style="display: inline-block; width: 16px; height: 3px; background: ${col.hex}; box-shadow: 0 0 6px ${col.hex}; border-radius: 2px;"></span>
        <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${col.hex}; box-shadow: 0 0 6px ${col.hex};"></span>
        <span style="color: ${col.hex}; font-weight: 600; font-family: Consolas, monospace; font-size: 0.8rem;">${escapeHtml(dst.ip)}</span>
      </div>
    `;
  });

  legend.innerHTML = itemsHtml;
}

function toggleGeoIPMode() {
  const mode = document.getElementById("geoip-mode")?.value || "single";
  const singleInp = document.getElementById("geoip-single-input");
  const flowInp = document.getElementById("geoip-flow-inputs");
  const modeStat = document.getElementById("geoip-stat-mode");
  if (singleInp) singleInp.style.display = mode === "single" ? "block" : "none";
  if (flowInp) flowInp.style.display = mode === "flow" ? "flex" : "none";
  if (modeStat) {
    modeStat.textContent = mode === "single" ? "單點 / 多節點定位" : "跨國流量路徑追蹤";
    modeStat.style.color = mode === "single" ? "var(--accent-cyan)" : "#a855f7";
  }
  resetGeoIPLegend();
}

function addSampleIP(ip) {
  const mode = document.getElementById("geoip-mode")?.value || "single";
  let targetInput = document.getElementById("geoip-ip");
  if (mode === "flow") {
    const active = document.activeElement;
    if (active && (active.id === "geoip-src-ip" || active.id === "geoip-dst-ip")) {
      targetInput = active;
    } else {
      targetInput = document.getElementById("geoip-dst-ip");
    }
  }
  if (!targetInput) return;
  const current = targetInput.value.trim();
  if (!current) {
    targetInput.value = ip;
  } else {
    const parts = current.split(/[\s,]+/).filter(Boolean);
    if (!parts.includes(ip)) {
      targetInput.value = current + ", " + ip;
    }
  }
}

function createCyberMarkerIcon(color = "red", customHex = null) {
  const pulseStyle = customHex ? `style="background: ${customHex}66;"` : "";
  const dotStyle = customHex ? `style="background: ${customHex}; color: ${customHex}; box-shadow: 0 0 10px ${customHex};"` : "";
  return L.divIcon({
    className: "cyber-marker-wrapper",
    html: `<div class="cyber-marker ${color}">
      <div class="cyber-marker-pulse" ${pulseStyle}></div>
      <div class="cyber-marker-dot" ${dotStyle}></div>
    </div>`,
    iconSize: [24, 24],
    iconAnchor: [12, 12],
    popupAnchor: [0, -14]
  });
}

function renderCountryDistribution(countriesMap, totalNodes) {
  const container = document.getElementById("geoip-country-list");
  const countEl = document.getElementById("geoip-country-count");
  if (!container) return;

  const sorted = Object.entries(countriesMap).sort((a, b) => b[1] - a[1]);
  if (countEl) countEl.textContent = `共 ${sorted.length} 國`;

  if (sorted.length === 0) {
    container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 2rem 0;">尚未載入節點資料</div>';
    return;
  }

  let html = "";
  sorted.forEach(([country, count], idx) => {
    const pct = totalNodes > 0 ? Math.round((count / totalNodes) * 100) : 0;
    html += `
      <div style="background: rgba(255, 255, 255, 0.03); border: 1px solid var(--card-border); border-radius: 6px; padding: 0.5rem 0.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem; margin-bottom: 0.25rem;">
          <span style="font-weight: 500; color: var(--text-primary);">
            <span style="color: var(--accent-cyan); font-family: monospace; font-size: 0.75rem; margin-right: 0.4rem;">#${idx + 1}</span>
            ${escapeHtml(country)}
          </span>
          <span style="font-size: 0.75rem; color: var(--text-muted); font-weight: 600;">${count} 處 (${pct}%)</span>
        </div>
        <div style="height: 4px; background: rgba(255, 255, 255, 0.08); border-radius: 2px; overflow: hidden;">
          <div style="height: 100%; width: ${pct}%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-purple)); border-radius: 2px;"></div>
        </div>
      </div>
    `;
  });
  container.innerHTML = html;
}

async function loadGeoIPPreset(presetType) {
  const runBtn = document.getElementById("geoip-run-btn");
  const origText = runBtn ? runBtn.innerHTML : "";
  if (runBtn) {
    runBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> 載入預設特徵中...';
    runBtn.disabled = true;
  }

  try {
    const presets = await apiFetch("/api/geoip/presets");
    if (presetType === "cti") {
      const modeSelect = document.getElementById("geoip-mode");
      if (modeSelect) modeSelect.value = "single";
      toggleGeoIPMode();
      const ips = (presets.cti_ips || []).map(x => x.ip);
      if (ips.length === 0) {
        alert("目前尚無 CTI 活躍惡意 IP");
        return;
      }
      const ipField = document.getElementById("geoip-ip");
      if (ipField) ipField.value = ips.join(", ");
      await runGeoIPQuery();
    } else if (presetType === "feodo") {
      const modeSelect = document.getElementById("geoip-mode");
      if (modeSelect) modeSelect.value = "single";
      toggleGeoIPMode();
      const ips = (presets.feodo_ips || []).map(x => x.ip);
      if (ips.length === 0) {
        alert("目前尚無 Feodo 殭屍網路 C2 節點");
        return;
      }
      const ipField = document.getElementById("geoip-ip");
      if (ipField) ipField.value = ips.join(", ");
      await runGeoIPQuery();
    } else if (presetType === "flow") {
      const modeSelect = document.getElementById("geoip-mode");
      if (modeSelect) modeSelect.value = "flow";
      toggleGeoIPMode();
      const flow = presets.flow_demo || {};
      const srcField = document.getElementById("geoip-src-ip");
      const dstField = document.getElementById("geoip-dst-ip");
      if (srcField) srcField.value = flow.source || "140.112.1.1";
      if (dstField) dstField.value = (flow.destinations || []).join(", ");
      await runGeoIPQuery();
    }
  } catch (e) {
    alert("載入預設資料失敗: " + e.message);
  } finally {
    if (runBtn) {
      runBtn.innerHTML = origText;
      runBtn.disabled = false;
    }
  }
}

async function runGeoIPQuery() {
  initGeoIPMap();
  const mode = document.getElementById("geoip-mode")?.value || "single";
  const runBtn = document.getElementById("geoip-run-btn");
  const origText = runBtn ? runBtn.innerHTML : "";
  if (runBtn) {
    runBtn.innerHTML = '<i class="fa-solid fa-satellite-dish fa-spin"></i> 正在查詢地理與路徑...';
    runBtn.disabled = true;
  }

  // Clear previous layers
  clearGeoIPMap();

  try {
    if (mode === "single") {
      const ipStr = document.getElementById("geoip-ip")?.value.trim() || "";
      if (!ipStr) {
        alert("請輸入至少一個 IP 位址！");
        return;
      }
      const ips = ipStr.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
      if (ips.length === 0) {
        alert("請輸入有效 IP 位址！");
        return;
      }

      const res = await apiFetch("/api/geoip/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips })
      });

      const list = res.list || Object.values(res.results || {}).filter(x => x.status === "success");
      if (!list || list.length === 0) {
        alert("未能定位到任何輸入 IP 的地理座標！");
        return;
      }

      const bounds = [];
      const countriesMap = {};
      const ispMap = {};

      list.forEach(r => {
        const lat = r.latitude || r.lat;
        const lon = r.longitude || r.lon;
        if (lat !== undefined && lon !== undefined && lat !== null && lon !== null) {
          const m = L.marker([lat, lon], {
            icon: createCyberMarkerIcon("red")
          }).addTo(geoipMap);

          const popupContent = `
            <div style="font-size: 0.85rem; line-height: 1.5; min-width: 200px;">
              <div style="font-weight: bold; font-size: 0.95rem; color: #38bdf8; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                <i class="fa-solid fa-crosshairs"></i> ${escapeHtml(r.ip)}
              </div>
              <div style="margin-bottom: 2px;"><span style="color: #94a3b8;">國家/城市:</span> <strong style="color: #f1f5f9;">${escapeHtml(r.country || "-")}</strong> ${escapeHtml(r.city ? `(${r.city})` : "")}</div>
              <div style="margin-bottom: 2px;"><span style="color: #94a3b8;">自治系統:</span> ${escapeHtml(r.as || "-")}</div>
              <div style="margin-bottom: 4px;"><span style="color: #94a3b8;">ISP 業者:</span> ${escapeHtml(r.isp || "-")}</div>
              <div style="font-size: 0.75rem; color: #64748b; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 4px;">座標: [${lat.toFixed(4)}, ${lon.toFixed(4)}]</div>
            </div>
          `;
          m.bindPopup(popupContent);
          geoipMarkers.push(m);
          bounds.push([lat, lon]);

          const cName = r.country || "未知國家";
          countriesMap[cName] = (countriesMap[cName] || 0) + 1;

          const ispName = r.isp || r.org || "未知 ISP";
          ispMap[ispName] = (ispMap[ispName] || 0) + 1;
        }
      });

      // Update stats
      document.getElementById("geoip-stat-nodes").textContent = bounds.length;
      const uniqueCountries = Object.keys(countriesMap).length;
      document.getElementById("geoip-stat-countries").textContent = uniqueCountries;

      const topIspEntry = Object.entries(ispMap).sort((a, b) => b[1] - a[1])[0];
      const ispStat = document.getElementById("geoip-stat-isp");
      if (topIspEntry && ispStat) {
        ispStat.textContent = `${topIspEntry[0]} (${topIspEntry[1]})`;
        ispStat.title = topIspEntry[0];
      }

      renderCountryDistribution(countriesMap, bounds.length);
      resetGeoIPLegend();

      if (bounds.length > 0) {
        geoipMap.fitBounds(bounds, { padding: [50, 50], maxZoom: 8 });
      }
    } else {
      // Flow mode (Multi-Source to Multi-Destination)
      const srcStr = document.getElementById("geoip-src-ip")?.value.trim() || "";
      const dstStr = document.getElementById("geoip-dst-ip")?.value.trim() || "";
      if (!srcStr || !dstStr) {
        alert("請輸入至少一個來源節點 IP 與目的節點 IP！");
        return;
      }

      const srcIps = srcStr.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
      const dstIps = dstStr.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);

      if (srcIps.length === 0 || dstIps.length === 0) {
        alert("請輸入有效來源 IP 與目的 IP！");
        return;
      }

      const allIps = Array.from(new Set([...srcIps, ...dstIps]));

      const res = await apiFetch("/api/geoip/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips: allIps })
      });

      const resMap = res.results || {};

      // Resolve valid source nodes
      const validSrcNodes = [];
      srcIps.forEach(ip => {
        const d = resMap[ip];
        const lat = d?.latitude ?? d?.lat;
        const lon = d?.longitude ?? d?.lon;
        if (lat !== undefined && lon !== undefined && lat !== null && lon !== null) {
          validSrcNodes.push({ ip, data: d, lat, lon });
        }
      });

      // Resolve valid destination nodes
      const validDstNodes = [];
      dstIps.forEach(ip => {
        const d = resMap[ip];
        const lat = d?.latitude ?? d?.lat;
        const lon = d?.longitude ?? d?.lon;
        if (lat !== undefined && lon !== undefined && lat !== null && lon !== null) {
          validDstNodes.push({ ip, data: d, lat, lon });
        }
      });

      if (validSrcNodes.length === 0) {
        alert(`無法獲取任何來源 IP (${srcIps.join(", ")}) 之地理座標，請確認 IP 格式。`);
        return;
      }
      if (validDstNodes.length === 0) {
        alert(`無法獲取任何目的 IP (${dstIps.join(", ")}) 之地理座標，請確認 IP 格式。`);
        return;
      }

      // Assign distinct vibrant colors to each destination
      validDstNodes.forEach((dstNode, idx) => {
        dstNode.color = FLOW_DEST_COLORS[idx % FLOW_DEST_COLORS.length];
      });

      const allBounds = [];
      const countriesMap = {};
      const ispMap = {};
      const renderedNodeKeys = new Set();

      // Render Source Markers (Cyan Pulse)
      validSrcNodes.forEach(srcNode => {
        const srcCoord = [srcNode.lat, srcNode.lon];
        allBounds.push(srcCoord);

        const nodeKey = `src-${srcNode.ip}`;
        if (!renderedNodeKeys.has(nodeKey)) {
          renderedNodeKeys.add(nodeKey);
          const srcMarker = L.marker(srcCoord, {
            icon: createCyberMarkerIcon("cyan")
          }).addTo(geoipMap);

          srcMarker.bindPopup(`
            <div style="font-size: 0.85rem; line-height: 1.5; min-width: 200px;">
              <div style="font-weight: bold; font-size: 0.95rem; color: #06b6d4; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                <i class="fa-solid fa-crosshairs"></i> 攻擊來源節點 (Source)
              </div>
              <div><strong style="color: #fff;">${escapeHtml(srcNode.ip)}</strong></div>
              <div><span style="color: #94a3b8;">國家/城市:</span> <strong style="color: #f1f5f9;">${escapeHtml(srcNode.data.country || "-")}</strong> ${escapeHtml(srcNode.data.city ? `(${srcNode.data.city})` : "")}</div>
              <div><span style="color: #94a3b8;">自治系統:</span> ${escapeHtml(srcNode.data.as || "-")}</div>
              <div><span style="color: #94a3b8;">ISP 業者:</span> ${escapeHtml(srcNode.data.isp || "-")}</div>
              <div style="font-size: 0.75rem; color: #64748b; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 4px; margin-top: 4px;">座標: [${srcNode.lat.toFixed(4)}, ${srcNode.lon.toFixed(4)}]</div>
            </div>
          `);
          geoipMarkers.push(srcMarker);

          const cName = srcNode.data.country || "未知國家";
          countriesMap[cName] = (countriesMap[cName] || 0) + 1;
          const ispName = srcNode.data.isp || srcNode.data.org || "未知 ISP";
          ispMap[ispName] = (ispMap[ispName] || 0) + 1;
        }
      });

      // Render Destination Markers with Distinct Color per Target
      validDstNodes.forEach((dstNode, idx) => {
        const dstCoord = [dstNode.lat, dstNode.lon];
        allBounds.push(dstCoord);

        const nodeKey = `dst-${dstNode.ip}`;
        if (!renderedNodeKeys.has(nodeKey)) {
          renderedNodeKeys.add(nodeKey);
          const dstMarker = L.marker(dstCoord, {
            icon: createCyberMarkerIcon(dstNode.color.name, dstNode.color.hex)
          }).addTo(geoipMap);

          dstMarker.bindPopup(`
            <div style="font-size: 0.85rem; line-height: 1.5; min-width: 220px;">
              <div style="font-weight: bold; font-size: 0.95rem; color: ${dstNode.color.hex}; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: ${dstNode.color.hex}; box-shadow: 0 0 6px ${dstNode.color.hex};"></span>
                目的受害節點 (Target #${idx + 1})
              </div>
              <div><strong style="color: #fff;">${escapeHtml(dstNode.ip)}</strong></div>
              <div><span style="color: #94a3b8;">國家/城市:</span> <strong style="color: #f1f5f9;">${escapeHtml(dstNode.data.country || "-")}</strong> ${escapeHtml(dstNode.data.city ? `(${dstNode.data.city})` : "")}</div>
              <div><span style="color: #94a3b8;">自治系統:</span> ${escapeHtml(dstNode.data.as || "-")}</div>
              <div><span style="color: #94a3b8;">ISP 業者:</span> ${escapeHtml(dstNode.data.isp || "-")}</div>
              <div style="font-size: 0.75rem; color: #94a3b8; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 4px; margin-top: 4px; display: flex; justify-content: space-between;">
                <span>座標: [${dstNode.lat.toFixed(2)}, ${dstNode.lon.toFixed(2)}]</span>
                <span style="color: ${dstNode.color.hex}; font-weight: 600;">● ${dstNode.color.label}</span>
              </div>
            </div>
          `);
          geoipMarkers.push(dstMarker);

          const cName = dstNode.data.country || "未知國家";
          countriesMap[cName] = (countriesMap[cName] || 0) + 1;
          const ispName = dstNode.data.isp || dstNode.data.org || "未知 ISP";
          ispMap[ispName] = (ispMap[ispName] || 0) + 1;
        }
      });

      // Render flow lines with matching destination color
      validSrcNodes.forEach(srcNode => {
        const srcCoord = [srcNode.lat, srcNode.lon];
        validDstNodes.forEach(dstNode => {
          const dstCoord = [dstNode.lat, dstNode.lon];

          // Avoid drawing zero-length line if source and destination are the exact same IP
          if (srcNode.ip === dstNode.ip) return;

          const lineColor = dstNode.color.hex;
          const line = L.polyline([srcCoord, dstCoord], {
            color: lineColor,
            weight: 2.5,
            opacity: 0.85,
            dashArray: "8, 6"
          }).addTo(geoipMap);
          geoipLines.push(line);

          // If polylineDecorator exists, add glowing directional arrow in destination's color
          if (typeof L.polylineDecorator === "function") {
            try {
              const arrow = L.polylineDecorator(line, {
                patterns: [
                  {
                    offset: "72%",
                    repeat: 0,
                    symbol: L.Symbol.arrowHead({
                      pixelSize: 11,
                      polygon: false,
                      pathOptions: { stroke: true, color: lineColor, weight: 2.5 }
                    })
                  }
                ]
              }).addTo(geoipMap);
              geoipMarkers.push(arrow);
            } catch (e) {
              console.debug("Decorator error:", e);
            }
          }
        });
      });

      // Update stats
      const totalDistinctNodes = renderedNodeKeys.size;
      document.getElementById("geoip-stat-nodes").textContent = totalDistinctNodes;
      document.getElementById("geoip-stat-countries").textContent = Object.keys(countriesMap).length;

      const topIspEntry = Object.entries(ispMap).sort((a, b) => b[1] - a[1])[0];
      const ispStat = document.getElementById("geoip-stat-isp");
      if (topIspEntry && ispStat) {
        ispStat.textContent = `${topIspEntry[0]} (${topIspEntry[1]})`;
        ispStat.title = topIspEntry[0];
      }

      renderCountryDistribution(countriesMap, totalDistinctNodes);

      // Update dynamic flow legend with colored destination badges
      updateFlowGeoIPLegend(validDstNodes);

      if (allBounds.length > 0) {
        geoipMap.fitBounds(allBounds, { padding: [60, 60], maxZoom: 6 });
      }
    }
  } catch (e) {
    alert("GeoIP 查詢失敗: " + e.message);
  } finally {
    if (runBtn) {
      runBtn.innerHTML = origText;
      runBtn.disabled = false;
    }
  }
}

// -------------------------------------------------------------
// UTILS
// -------------------------------------------------------------
function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function renderPaginationControls(containerId, currentPage, totalPages, onPageClick) {
  const container = document.getElementById(containerId);
  if (!container) return;

  if (totalPages <= 1) {
    container.innerHTML = "";
    return;
  }

  let html = "";
  html += `<button class="btn btn-secondary" style="padding: 0.25rem 0.5rem;" ${currentPage <= 1 ? "disabled" : ""} onclick="(${onPageClick.toString()})(${currentPage - 1})"><i class="fa-solid fa-chevron-left"></i></button>`;

  const maxButtons = 5;
  let start = Math.max(1, currentPage - 2);
  let end = Math.min(totalPages, start + maxButtons - 1);
  if (end - start < maxButtons - 1) {
    start = Math.max(1, end - maxButtons + 1);
  }

  for (let i = start; i <= end; i++) {
    html += `<button class="btn ${i === currentPage ? "btn-primary" : "btn-secondary"}" style="padding: 0.25rem 0.6rem; min-width: 32px;" onclick="(${onPageClick.toString()})(${i})">${i}</button>`;
  }

  html += `<button class="btn btn-secondary" style="padding: 0.25rem 0.5rem;" ${currentPage >= totalPages ? "disabled" : ""} onclick="(${onPageClick.toString()})(${currentPage + 1})"><i class="fa-solid fa-chevron-right"></i></button>`;

  container.innerHTML = html;
}

// -------------------------------------------------------------
// INITIALIZATION ON DOM READY
// -------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  fetchStatus();
  // Auto refresh status every 30 seconds
  setInterval(() => {
    if (currentTab === "dashboard") {
      fetchStatus();
    }
  }, 30000);
});
