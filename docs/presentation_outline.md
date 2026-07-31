# On-Demand Atelier

---

## テーマの目的

**LLMを活用したマルウェア生成の完全自動化**

- レッドチーム演習・ペネトレーションテストにおいて、ターゲット環境に特化したカスタムマルウェアを**オンデマンドで自動生成**する
- 従来の手動開発（数日〜数週間）を、YAML仕様の入力だけで**数十分**に短縮する
- 毎回ユニークなバイナリを生成し、シグネチャベースの検知を根本的に回避する

---

## 最終目標: On-Demand Malware Framework

```
spec.yaml  →  [Pipeline]  →  機能するEDR回避型バイナリ
  (5行)        (自動)           (数十分で完成)
```

**「欲しいマルウェアを、欲しいときに、欲しい形で」**

- 入力: マルウェアの種類・ターゲットOS・回避対象EDR（YAML 5〜10行）
- 出力: コンパイル済みバイナリ（.exe / .dll / shellcode）
- 対応タイプ: Ransomware / Infostealer / Keylogger / RAT
- 対応言語: C / Go
- 対応OS: Windows 11（Linux拡張予定）

---

## パイプライン全体像

```
[1] Spec解析 → [2] LLM計画生成 → [3] チャンク別コード生成
        ↓
[4] 自動コンパイル修正 → [5] 回避パス適用 → [6] VM自動デプロイ
        ↓
[7] 機能検証（キャナリー） → [8] EDR検知テスト → [9] 成功 or 再試行ループ
```

| ステップ | 技術 |
|---|---|
| コード生成 | ローカルLLM（Qwen3-35B / Blackwell） |
| コンパイル | MinGW クロスコンパイル |
| 回避技術 | 文字列暗号化, API動的解決, AMSI/ETW bypass, SEH, アンチデバッグ |
| VM環境 | QEMU/OVMF + Windows 11 自動プロビジョニング |
| 機能検証 | キャナリーファイルベース（偽陽性ゼロ） |
| EDR検知 | Windows Defender / Wazuh / OpenEDR 対応 |

---

## 期待する結果

1. **spec.yaml入力のみでエンドツーエンド完結**
   - 人間のコーディング・デバッグ介入ゼロ

2. **生成コードの品質保証**
   - コンパイルエラー自動修復（ヘッダー補正、API名修正、構文修正）
   - 機能検証: 実際にファイルが暗号化されたか、情報が窃取されたかをキャナリーで確認

3. **EDR回避率の向上**
   - 毎回異なるバイナリ = シグネチャ検知不可
   - 多層回避パス自動適用

4. **反復改善ループ**
   - 検知された場合 → 回避手法を自動変更 → 再生成 → 再テスト

---

## インパクト

| Before (従来) | After (本フレームワーク) |
|---|---|
| カスタムマルウェア開発: **数日〜数週間** | **コマンド一発、数十分** |
| 回避手法の適用: 手動で毎回実装 | **自動適用、6種以上の回避パス** |
| EDRテスト: 手動で環境構築・実行 | **VM自動プロビジョニング＋自動テスト** |
| 検知時の対応: 手動で書き直し | **自動再試行ループ** |
| バイナリの一意性: 意識的に変える必要あり | **毎回自動で一意** |

**（例）ペネトレーションテスト案件でのマルウェア準備時間が数日→30分に短縮！**

---

## 現状の進捗

### 完了済み
- パイプライン基盤（計画→生成→組立→コンパイル→検証ループ）
- 6種の回避パス（文字列暗号化、API難読化、AMSI/ETW bypass、SEH、アンチデバッグ、プロセスインジェクション）
- VM自動プロビジョニング（QEMU/OVMF + Windows 11 autounattend）
- キャナリーベース機能検証（偽陽性対策済み）
- LLM生成コードの自動修復（ヘッダー幻覚補正、API名修正、構文修正）
- ユニットテスト94件 + E2Eテスト15件

### 進行中
- E2Eテストスイートの安定化（LLM生成品質の非決定性対策）
- VM上での実マルウェア実行検証（ransomware, infostealer, keylogger, RAT）

### 今後
- Go言語対応の強化
- 追加マルウェアタイプ（dropper, backdoor）
- マルチEDR同時テスト
- Webポータル（生成・監視UI）

---

## つまづきポイント・課題

| 課題 | 対策 |
|---|---|
| LLMのコード生成品質が非決定的 | 多段修復パイプライン（6回リトライ + コンパイル修正ループ） |
| LLMがヘッダー名を幻覚する | ファジーマッチ補正（`tllib32.h` → `tlhelp32.h`） |
| LLMがプロンプト文脈をコードに混入 | prose leak除去フィルター |
| 機能検証の偽陽性 | LLM判定 → キャナリー判定に権限移行 |
| ローカルLLMの同時リクエスト不可 | パイプライン直列実行制御 |

---

## デモ（実行例）

```yaml
# spec.yaml (入力はこれだけ)
malware_type: ransomware
language: c
target:
  os: windows_11
  edrs: [windows_defender]
```

```bash
$ python3 -m atelier run --spec spec.yaml --output results/
```

```
[Pipeline] Plan generated: 6 components
[Pipeline] Code generated: 12,847 chars
[Pipeline] Compiled successfully (x86_64-w64-mingw32-gcc)
[Pipeline] VM deployed, executing...
[Pipeline] Functional validation: PASS (3/3 canary files encrypted)
[Pipeline] EDR detection: CLEAN (Windows Defender)
[Pipeline] SUCCESS → results/malware.exe
```
