# RAGLeakGuard

[![PyPI](https://img.shields.io/pypi/v/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![Downloads](https://img.shields.io/pypi/dm/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![CI](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenvana/RAGLeakGuard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/ragleakguard)](https://pypi.org/project/ragleakguard/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[English](README.md) | **繁體中文**

RAGLeakGuard 是早期開發中的靜態資料敏感資訊診斷安全專案。儲存庫仍包含偵測、風險政策、
監控狀態及已驗證 webhook 元件。目前已實作一個有界限、僅回傳聚合結果的 Chroma 操作員快照
連接器；直接／即時來源 store 掃描仍停用。

## Chroma 安全通知

直接／即時 Chroma 掃描仍停用。可執行的端點證據證實：ChromaDB 1.5.0 與 1.5.9 在建立
client 或讀取時，可能修改持久化 store 檔案。其他 Chroma 版本尚未建立可接受的唯讀邊界。
這是確切的測試範圍，不代表所有 Chroma 版本都已測試。

[Issue #15](https://github.com/Agenvana/RAGLeakGuard/issues/15) 已以 `not planned` 延後，
並未完成。WP7B 的私有、有界限 operator-snapshot confinement 基礎已在確切 implementation
head `128decb3e0d78825e884f6dce019898b568c6ba2` 通過獨立審查，並透過
[PR #20](https://github.com/Agenvana/RAGLeakGuard/pull/20) 以 merge commit
`5db765689d35eec8ba918f0f616d5fea34e56955` 合併。WP7D 現在只透過該私有 work copy 使用
WP7C 的雙次列舉，並在隔離 worker 內執行偵測。公開啟用僅限 ChromaDB 1.5.9：Linux/ext4
Python 3.10–3.12、macOS 15/APFS Python 3.12，以及 Windows/NTFS Python 3.12。
ChromaDB 1.5.0 僅保留為私有證據，公開路徑會拒絕它。

操作員（不是 RAGLeakGuard）必須先建立完整且靜止的 full-filesystem snapshot。
RAGLeakGuard 不會證明快照的來源、靜止狀態、完整性或原子一致性。快照仍是可能惡意且敏感的
輸入。本專案不宣稱一般 Chroma 支援、即時來源唯讀、連接器完整性或正式環境安全性。

PyPI `0.1.0` 套件包含不安全的直接 Chroma 路徑，**不得用於 Chroma 掃描**。撤下該套件
與發布修正版都需要人類維護者另行授權；此儲存庫變更沒有執行這些動作。

## 修正版狀態

`0.1.1` 是 source 中提議的修正版；尚未發布、建立 tag 或建立 GitHub release。Hatch 以
`ragleakguard.__version__` 作為唯一版本來源。build-once 的 `release-candidate.yml` workflow
只有唯讀 repository 權限，沒有發布 credential，也沒有 OIDC `id-token` 權限。它只從一個
確切 commit 建立 wheel 與 sdist，檢查並計算 hash，並以實際安裝的 artifact 完成測試後，
才會產生僅供獨立審查的 candidate evidence。

提議的 base／`detect` 套件矩陣是 Ubuntu 24.04/ext4、macOS 15/APFS、Windows Server
2025/NTFS 上的 CPython 3.9–3.12；package metadata 有明確上限 `>=3.9,<3.13`。這十二格套件
矩陣不會擴大 Chroma 支援；公開 snapshot 啟用仍只限上述 ChromaDB 1.5.9 的五格矩陣。
詳見 canonical [0.1.1 修正版 release notes](docs/releases/0.1.1.md) 與
[release process](docs/RELEASE_PROCESS.md)。

另一個 `publish-pypi.yml` workflow 僅能手動觸發且目前 dormant。它絕不重建 artifact，並要求
完全相符的 annotated tag、commit、version、candidate run、artifact hash、既有且受保護的
`pypi` environment，以及在 PyPI 外部設定的 OIDC Trusted Publishing。WP8 不會建立任何這些
發布權限，也不會發布任何套件。

## 目前命令行為

`scan --source chroma` 只接受 `--snapshot`、`--work-parent`、窄範圍的假名
`--source-id`、明確的 `--acknowledge-offline-complete-snapshot`、選用 `--locale` 與
`--report`。舊的 `--path` 會在來源存取前被拒絕。只有在有界限複製、雙次列舉、完整偵測、
聚合計數完全相等、worker 終止、最終 capability 驗證、cleanup 與原子報告完成後才會輸出成功。
`read_chroma()` 仍不會檢查傳入物件，並立即同步拋出 `ChromaConnectorUnavailableError`。

`monitor` 會先驗證 key 與 state。若已驗證的狀態含有 WP6 pending alert，既有的設定、
backoff、retry、transport、ambiguous-delivery 及原子清除復原流程會在不開始新掃描的情況下
執行。若沒有 pending alert，且原本將開始新掃描，`monitor` 會以 exit code 6 停止，不修改
狀態，也不建立報告、alert 或 webhook。

一般缺少選項、不支援的來源、格式錯誤或不支援的 locale 仍以 exit code 2 結束；掃描／報告
不確定性使用 exit code 1，偵測 runtime 問題使用 exit code 3，候選版本或啟用環境不可用使用
exit code 6。監控 key／state 錯誤維持 exit code 4；pending alert 與 webhook 錯誤維持 exit code 5。

只可對另行建立的離線操作員快照執行：

```bash
python -m pip install ".[chroma-snapshot,detect]"
python -m spacy download en_core_web_sm
ragleakguard scan --source chroma \
  --snapshot /private/offline-snapshot \
  --work-parent /private/ragleakguard-work \
  --source-id source-1 \
  --acknowledge-offline-complete-snapshot \
  --report /private/reports/source-1.md
```

上述路徑只是 placeholder，不會出現在一般 console 輸出或報告中。monitor 新掃描仍不可用，
所以文件不提供 Chroma monitor quickstart。

## 開發環境

Chroma 不在 base dependency 中。以下安裝精確的 snapshot 候選版本、偵測堆疊與測試工具。

```bash
git clone https://github.com/Agenvana/RAGLeakGuard.git
cd RAGLeakGuard
python -m venv .venv
# 依作業系統啟用環境。
python -m pip install --upgrade pip
python -m pip install -e ".[chroma-snapshot,detect,dev]"
python -m spacy download en_core_web_sm
python -m pytest -q
```

確定性的 Chroma seed／evaluation 腳本只保留作為歷史研究及開發 fixture。它們不是受支援的
掃描流程，絕不可用於真實、正式環境、客戶或其他敏感 store。

## 偵測能力

- **預設函式庫設定：**全域與美國 Presidio recognizer。
- **在地包（`--locale`）：**`au` 是目前唯一已實作、可選用的國家在地包。

偵測是 best-effort。偵測函式庫的結果不能證明資料安全、合規或不含敏感資訊。必要的 spaCy
model 必須預先安裝；隔離 worker 會拒絕 model 下載、網路 egress 與額外 process。

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

詳見 [ROADMAP.md](ROADMAP.md)。上述有限的操作員快照 connector 已實作。其他 connector、
直接／即時掃描、monitor 新掃描、Prevent/Fix、Prove、Control Plane、刪除證明、合規、認證
及 assurance 介面都尚未實作。

## 授權條款

Apache-2.0
