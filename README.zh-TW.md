# RAGLeakGuard

[![PyPI](https://img.shields.io/pypi/v/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![Downloads](https://img.shields.io/pypi/dm/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![CI](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[English](README.md) | **繁體中文**

RAGLeakGuard 是早期開發中的靜態資料敏感資訊診斷安全專案。儲存庫仍包含偵測、風險政策、
監控狀態及已驗證 webhook 元件，但**目前沒有任何可用的來源掃描連接器**。

## Chroma 安全通知

直接掃描本機 Chroma 已停用。可執行的端點證據證實：ChromaDB 1.5.0 與 1.5.9 在建立
client 或讀取時，可能修改持久化 store 檔案。其他 Chroma 版本尚未建立可接受的唯讀邊界。
這是確切的測試範圍，不代表所有 Chroma 版本都已測試。

[Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) 已以 `not planned` 延後，
並未完成。以 snapshot 為基礎的支援正接受另一項可行性與安全審查；目前未實作，也不保證
未來會提供。本專案不宣稱 Chroma 支援版本範圍、未來可用性、連接器完整性、來源唯讀或
正式環境安全性。

PyPI `0.1.0` 套件包含不安全的直接 Chroma 路徑，**不得用於 Chroma 掃描**。撤下該套件
與發布修正版都需要人類維護者另行授權；此儲存庫變更沒有執行這些動作。

## 目前命令行為

語法有效的 `scan --source chroma` 會以 exit code 6 和固定訊息停止；停止發生在 Chroma
import、偵測器初始化、來源存取、報告處理及成功輸出之前。`read_chroma()` 不會檢查傳入
物件，呼叫時會立即同步拋出公開的 `ChromaConnectorUnavailableError`。

`monitor` 會先驗證 key 與 state。若已驗證的狀態含有 WP6 pending alert，既有的設定、
backoff、retry、transport、ambiguous-delivery 及原子清除復原流程會在不開始新掃描的情況下
執行。若沒有 pending alert，且原本將開始新掃描，`monitor` 會以 exit code 6 停止，不修改
狀態，也不建立報告、alert 或 webhook。

一般缺少選項、不支援的來源、格式錯誤或不支援的 locale 仍以 exit code 2 結束。監控 key／
state 錯誤維持 exit code 4；pending alert 與 webhook 錯誤維持 exit code 5。

```text
Local Chroma scanning is disabled because executable endpoint evidence proved that ChromaDB 1.5.0 and 1.5.9 may modify durable store files during client construction or reads, while other versions have not established an acceptable read-only boundary. No report, monitor state, or webhook was created or replaced.
```

直接存取停用期間，文件刻意不提供可執行的 Chroma scan 或 monitor quickstart。

## 開發環境

Chroma runtime extra 已移除。以下只安裝套件、偵測堆疊與測試工具，不會提供來源掃描連接器。

```bash
git clone https://github.com/Agenvana/RAGLeakGuard.git
cd RAGLeakGuard
python -m venv .venv
# 依作業系統啟用環境。
python -m pip install --upgrade pip
python -m pip install -e ".[detect,dev]"
python -m spacy download en_core_web_sm
python -m pytest -q
```

確定性的 Chroma seed／evaluation 腳本只保留作為歷史研究及開發 fixture。它們不是受支援的
掃描流程，絕不可用於真實、正式環境、客戶或其他敏感 store。

## 偵測能力

- **預設函式庫設定：**全域與美國 Presidio recognizer。
- **在地包（`--locale`）：**`au` 是目前唯一已實作、可選用的國家在地包。

偵測是 best-effort。偵測函式庫的結果不能證明資料安全、合規或不含敏感資訊。缺少模型時，
Presidio 可能在初始化期間嘗試取得模型；runtime 下載控制與精確模型鎖定仍是待加強事項。
停用的新掃描 CLI 路徑不會初始化此 runtime。

## Monitor 復原

已驗證的 version-3 state 與 protocol-v2 webhook 設計記錄於
[monitor state contract](docs/MONITOR_STATE.md) 與 [webhook protocol](docs/WEBHOOK_PROTOCOL.md)。
Pending recovery 不會存取 Chroma，也不能建立新的掃描衍生 alert。`2xx` 回應只允許已核准的
原子 outbox-clear 轉換；這不證明 exactly-once delivery、下游處理或人員通知。

Credential helper 仍可使用：

```bash
ragleakguard generate-monitor-key --output rlg-monitor-key.json
ragleakguard generate-webhook-secret --output rlg-webhook-secret.json
```

復原需要原本的 `--key-file`、已驗證的 `--state`；若有 pending alert，另需 protocol-v2
`--webhook-secret-file` 與已驗證的 HTTPS receiver。使用 `--initialize` 建立新 baseline 已停用，
因為它需要開始新掃描。無效 key／state 以 exit code 4 結束；pending 設定、backoff、retry、
preparation、transport 或 response 失敗以 exit 5 結束。Slack 與 Discord incoming webhook
不相容，因為復原需要 protocol-v2 專用 verifier 及 durable delivery-ID deduplication。

## 歷史研究

2026 年 7 月的 [AI Data Security Report](reports/AI-Data-Security-Report-01-2026-07.pdf)
及其來源歷史是凍結的歷史證據，不代表目前連接器可用或安全。詳見
[benchmark reproducibility](docs/BENCHMARK_REPRODUCIBILITY.md)。

## 路線圖與非保證事項

詳見 [ROADMAP.md](ROADMAP.md)。規劃中的連接器、snapshot 可行性工作、Prevent/Fix、Prove、
Control Plane、刪除證明、合規、認證及 assurance 介面都尚未實作。

## 授權條款

Apache-2.0
