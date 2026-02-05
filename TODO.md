# DNSVet タスクリスト

*v0.8.1時点でのチェック結果*

---

## 🔴 Critical (即対応)

### CI/CD
- [ ] **GitHub Actions追加** - `.github/workflows/ci.yml`
  - [ ] `npm test` on push/PR
  - [ ] Node 18/20/22 マトリクステスト
  - [ ] npm publish (tag push時)
- [ ] **npm publish準備**
  - [ ] `npm pack --dry-run` でパッケージ内容確認
  - [ ] `.npmignore` or `files` フィールド設定
  - [ ] `engines` フィールド追加 (Node >= 18)

### テスト
- [ ] **テストカバレッジ導入** - `@vitest/coverage-v8`
- [ ] **AWS/GCP/Azure source テスト追加** - CLI呼び出しのモック
- [ ] **analyzer.ts 統合テスト追加** - E2Eフロー
- [ ] **cli.ts テスト追加** - コマンド引数パース、出力

---

## 🟠 High (1週間以内)

### 機能強化
- [ ] **SARIF出力** - GitHub Code Scanning連携 `--format sarif`
- [ ] **HTML/Markdownレポート** - `--format html|markdown`
- [ ] **--diff オプション** - 前回結果との差分比較
- [ ] **Slack/Discord webhook** - 通知連携
- [ ] **プログレス表示** - 大量スキャン時の進捗バー

### チェック精度向上
- [ ] **DNSSEC RRSIG検証** - dig依存からDoH/DoTベースへ
- [ ] **BIMI SVG検証** - ロゴファイルの実体確認
- [ ] **BIMI VMC証明書検証** - 証明書の有効期限・発行者チェック
- [ ] **MTA-STS MX整合性エラー詳細化** - どのMXがマッチしないか明示
- [ ] **TLS-RPT エンドポイント検証強化** - 証明書エラー、リダイレクト追跡

### ドキュメント
- [ ] **CONTRIBUTING.md** - コントリビューションガイド
- [ ] **CHANGELOG.md** - バージョン履歴
- [ ] **API.md** - プログラマティック利用ガイド
- [ ] **man page** - `dnsvet.1` (optional)

---

## 🟡 Medium (2週間以内)

### テスト拡充
- [ ] **DNSSEC実行テスト** - digモック or DoH経由
- [ ] **MTA-STS HTTPエラー網羅** - 404, 500, タイムアウト, TLSエラー
- [ ] **TLS-RPT 405→GETフォールバック テスト**
- [ ] **IDNドメイン E2Eテスト** - 日本語/絵文字ドメイン
- [ ] **大量ドメインスキャン性能テスト**

### コード品質
- [ ] **ESLint設定強化** - `@typescript-eslint/recommended`
- [ ] **Prettier追加** - コードフォーマット統一
- [ ] **src/index.ts エクスポート整理** - 新機能(checkBIMI, checkMTASTS等)追加
- [ ] **GCP console.error → logger抽象化**
- [ ] **エラーコード体系** - DNSVETxxx形式

### CLI/UX
- [ ] **NO_COLOR/CI環境検出** - 色付け自動無効化
- [ ] **--quiet オプション** - エラーのみ出力
- [ ] **--fail-on <grade>** - 指定グレード以下で終了コード1
- [ ] **--include-passing** - 全チェック詳細表示(passed含む)
- [ ] **タブ補完スクリプト** - bash/zsh/fish

### 機能追加
- [ ] **CAA レコードチェック** - 証明書発行ポリシー
- [ ] **DANE (TLSA) チェック** - DNS-based認証
- [ ] **ドメインレピュテーション** - ブラックリストチェック (optional)
- [ ] **複数resolver対応** - `--resolver 8.8.8.8,1.1.1.1`

---

## 🟢 Low (バックログ)

### パフォーマンス
- [ ] **DNS結果の永続キャッシュ** - ファイルベースキャッシュ (optional)
- [ ] **並列度の自動調整** - DNS rate limit検出
- [ ] **ストリーミング出力** - 大量結果のメモリ効率化

### 拡張性
- [ ] **プラグインシステム** - カスタムチェック追加
- [ ] **設定ファイル対応** - `.dnsvetrc.json`
- [ ] **レポートテンプレート** - カスタムフォーマット

### その他
- [ ] **Docker イメージ** - `ghcr.io/taku-tez/dnsvet`
- [ ] **Web UI** - 簡易Webインターフェース
- [ ] **VS Code拡張** - ホバーでDNS情報表示

---

## 📊 現状サマリー

| カテゴリ | 状態 |
|---------|------|
| チェック機能 | 9種類 (SPF/DKIM/DMARC/MX/BIMI/MTA-STS/TLS-RPT/ARC/DNSSEC) |
| テスト | 113 passing |
| テストファイル | 13 |
| ソースコード | ~5400行 |
| 依存関係 | 1 (commander) |
| TypeScript | strict mode ✅ |
| RFC準拠 | 7208(SPF), 7489(DMARC), 8461(MTA-STS), 7505(NullMX), 8624(DNSSEC) |
| クラウド対応 | AWS, GCP, Azure, Cloudflare |
| CI/CD | ❌ 未設定 |
| npm公開 | ❌ 未公開 |

---

## 🎯 優先度の判断基準

1. **Critical**: npm publish/CI/CD は公開前に必須
2. **High**: ユーザー価値が高い機能 + 品質向上
3. **Medium**: 完成度を高める改善
4. **Low**: nice-to-have

---

*最終更新: 2026-02-05*
