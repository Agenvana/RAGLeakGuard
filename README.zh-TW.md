# RAGLeakGuard

[![PyPI](https://img.shields.io/pypi/v/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![Downloads](https://img.shields.io/pypi/dm/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![CI](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[English](README.md) | **繁體中文**

> 掃描你的 AI 向量資料庫中暴露的敏感資料——在它變成一場無法刪除的資料外洩之前。

**RAGLeakGuard** 是一個 CLI 工具：連接你的向量資料庫（目前支援 Chroma，更多連接器開發中），讀取其中儲存的內容，偵測敏感資料（個資、醫療、金融），並產出**風險分級報告**。不需要改動你的應用程式——指向資料庫、執行掃描即可。

> **它是什麼：**一個*資料盤點與合規*掃描器——回答合規負責人真正會問的問題：
> *「我們的向量資料庫裡存放了哪些受監管的資料？我們能證明它可以被刪除嗎？」*
> 唯讀操作，可安全地對正式環境執行。
>
> **它不是什麼：**紅隊測試工具。它不會發動提示注入（prompt injection）或越獄攻擊——
> 它稽核的是**靜態資料**，而不是模型在攻擊下的反應。

> 🚧 早期開發中——公開打造（building in public）。尚未達到正式環境等級。

## 為什麼重要

RAG 系統會把你的私有資料嵌入（embed）到向量資料庫中。這些資料**可以從向量被還原**（embedding inversion 嵌入反推）、**難以刪除**（備份、副本、快取、微調模型），而且通常**沒有任何盤點清單**。RAGLeakGuard 幫你找出它們。

## 安裝

```bash
pip install "ragleakguard[chroma,detect]"   # 掃描器 + Chroma 連接器 + 偵測引擎
python -m spacy download en_core_web_sm      # 一次性安裝：NLP 模型（約 12 MB）
```

> **Python 3.9 提示：**相依套件已鎖定版本（`spaCy<3.8`、`numpy<2`），會直接使用預編譯 wheel——不需要從原始碼編譯。

<details>
<summary>或從原始碼安裝（開發用）</summary>

```bash
git clone https://github.com/Agenvana/RAGLeakGuard.git
cd RAGLeakGuard
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip          # 新建立的 venv 內建的 pip 較舊；可編輯安裝需要較新版本
pip install -e ".[chroma,detect,dev]"
python -m spacy download en_core_web_sm
```
</details>

## 快速開始（約 2 分鐘）

```bash
# 1. 建立一個充滿「假」敏感紀錄的測試向量資料庫
python scripts/seed_synthetic.py                          # -> ./sample_store（100 筆合成診所紀錄）

# 2. 掃描它——預設啟用全球 + 美國識別器
ragleakguard scan --source chroma --path ./sample_store --report report.md

# 3. 測試資料是澳洲格式，加上 AU 在地包（locale pack）可獲得完整覆蓋
ragleakguard scan --source chroma --path ./sample_store --locale au --report report.md

# 4. 打開 report.md（摘要、依類型與嚴重度的發現、風險等級、修補建議）
```

## Monitor（持續監控）

單次掃描告訴你今天的狀態；`monitor` 告訴你狀態何時改變：

```bash
# 產生本機 256-bit 監控金鑰；絕不覆寫既有路徑
ragleakguard generate-monitor-key --output rlg-monitor-key.json

# 產生新的 protocol-v2 webhook 密鑰；先把新的 key ID 與密鑰配置到
# 每個 receiver 節點，再讓 sender 指向此新檔案
ragleakguard generate-webhook-secret --output rlg-webhook-secret.json

# 明確授權建立新的、已驗證的 version-3 基準線
ragleakguard monitor --source chroma --path ./sample_store --locale au \
  --key-file rlg-monitor-key.json --state rlg-state.json --initialize

# 之後的執行會先以原子方式提交單一項目的 outbox，再嘗試最小化且已簽署的警報；
# receiver 必須驗證 protocol v2，並以 durable 方式去除重複 delivery ID
ragleakguard monitor --source chroma --path ./sample_store --locale au \
  --key-file rlg-monitor-key.json --state rlg-state.json \
  --webhook https://receiver.example.com/rlg \
  --webhook-secret-file rlg-webhook-secret.json

# 排入 cron（每小時）：exit 1 = 本次掃描發現暴露變更；exit 5 = pending/backoff、
# webhook 設定、建構、傳輸、重新導向或回應失敗
0 * * * *  ragleakguard monitor --source chroma --path /srv/store --key-file /etc/rlg/monitor-key.json --state /var/lib/rlg/state.json --webhook https://receiver.example.com/rlg --webhook-secret-file /etc/rlg/webhook-secret.json
```

已驗證的 version-3 狀態檔包含完整長度、以金鑰產生的範圍／紀錄 token、發現層級指紋、驗證計數，以及 `pending_alert: null` 或一個有界且最小化的 outbox 項目。該項目只含固定 event/version、隨機 128-bit delivery ID、已完成失敗嘗試次數與下次重試時間；不含 URL、key ID、密鑰、signature、來源／store 路徑、finding、count、response 或 exception。Version 1 仍會在不修改檔案的情況下被拒絕。有效且已驗證的 version-2 狀態會被視為沒有 pending alert，並只在下一次成功的原子狀態轉換時移轉；這無法復原 version 2 時期已遺失的警報。缺少、無效、不相符或未通過驗證的金鑰／狀態會在來源存取前以 exit code 4 結束。建立基準線必須使用 `--initialize`，且不會覆寫既有路徑。

Webhook 本體固定為同一個 60-byte protocol-v2 暴露變更事件。嚴格的 header allowlist 新增 persisted delivery ID；v2 signature 同時驗證該 ID、精確 URL target、本體、timestamp 與每次重新產生的 nonce。HTTPS 憑證鏈與主機名稱驗證不可停用、絕不跟隨重新導向，且 DNS、連線、TLS、傳送與回應 headers 共用一個 10 秒 monotonic deadline。Unsigned 設定及舊式 v1 密鑰檔／receiver 會 fail closed，不會自動 downgrade。Slack／Discord incoming webhook 不相容；Zapier、n8n 或其他下游服務必須先經過能驗證並 durable deduplicate 此協定的 receiver／gateway。

只要 alert 仍 pending，後續執行就不會存取來源。到期的執行最多嘗試一次，沿用同一 delivery ID，並重新產生 timestamp、nonce 與 signature。失敗會以有界 exponential full-jitter backoff 保留；不會因年齡或嘗試次數而默默丟棄。只有可接受的 `2xx` response headers 才允許原子清除本機 pending alert；清除失敗屬於 ambiguous delivery，之後可能重複傳送。Receiver 必須使用 durable、atomic deduplication，但這不證明 exactly-once processing、無條件 at-least-once delivery、下游處理或人員通知。此版本只支援單一 destination 與單一 pending alert；receiver outage 可無限期阻擋後續掃描，且沒有 dead-letter 管理。移轉、cutover、retry、復原與殘餘風險請見 [webhook 協定](docs/WEBHOOK_PROTOCOL.md)與[監控金鑰與狀態契約](docs/MONITOR_STATE.md)（英文）。

## 偵測能力

- **預設：**全球 + 美國識別器——SSN、銀行帳號、駕照、信用卡、Email、電話、姓名、地點、日期、IP、加密貨幣地址……
- **在地包（`--locale`）：**`au`（Medicare / 電話 / TFN / ABN / ACN）——目前唯一已實作、可選用的國家在地包。其他在地包僅列於[規劃](ROADMAP.md)，尚未實作。

語系代碼不分大小寫，並會忽略前後空白。格式錯誤或不支援的語系輸入會以 exit code 2 結束。如果偵測相依套件或所需的 spaCy 模型無法載入，使偵測執行階段無法完成初始化，命令會以 exit code 3 結束。兩項驗證都在存取來源前執行，因此失敗時不會寫入報告或監控狀態，也不會傳送 webhook。

缺少所需模型時，Presidio 可能會在初始化期間嘗試取得模型。RAGLeakGuard 目前未覆寫或停用 Presidio 的這項行為。如何控管執行階段模型取得，以及如何精確鎖定模型，仍是另外的殘餘強化議題。

## 📊 AI 資料安全報告（The AI Data Security Report）

每月發布、方法公開的報告，實測 AI 資料管線的真實外洩情況——使用本工具的基準測試腳本、以合成資料產出，可在你的機器上重現。**第 1 期（2026 年 7 月）：[Your AI's Privacy Filter Speaks American. It Missed 1 in 3 Australian IDs.](reports/AI-Data-Security-Report-01-2026-07.pdf)** 所有期數：[reports/](reports/)。

## 路線圖

見 **[ROADMAP.md](ROADMAP.md)**——接下來包括更多連接器（Pinecone、pgvector）、更多在地包（包含台灣：身分證字號與健保卡號），以及 **Fix** 層（**專利申請中 / patent pending**）：在嵌入*之前*就將敏感資料代碼化（tokenize），原始值只存放於安全保險庫（vault）；單一撤銷操作即可讓某人的資料在所有副本——包含備份、快取、複本——同時且不可逆地失效；再由 **Prove** 層產出可供稽核、附驗證重掃的刪除證明報告。

## 授權條款

Apache-2.0
