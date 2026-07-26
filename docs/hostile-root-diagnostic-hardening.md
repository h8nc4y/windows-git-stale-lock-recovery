# Hostile root path 診断のfail-closed化

## 区分

Class M（開発用validator / self-testの診断境界修正）。

## 目的

3 entrypointが解決不能または空白だけの明示 `-Path` を受け取ったとき、
入力pathやPowerShell標準error framingをstdout / stderrへ出さず、
entrypoint固有の固定診断だけで終了する。

scanner本体の `scan-root-resolution-failed` と同じprivacy原則を、
公開前検証を担う残り2 entrypointにも適用する。

## 影響

- 対象はroot path解決失敗時の診断とsynthetic regression fixtureだけ。
- `-Path` の省略と明示した空文字 / 空白を区別し、明示した無効scopeを
  repo既定rootへ黙って置き換えない。
- readinessの成功表示は検証対象rootを再掲しない固定文言にする。
- 正常なreadiness、self-test、scanner、Git child、五点チェック、
  lock削除範囲は変更しない。
- 実repoのlock、他processのlock、実データは作成・読取・削除しない。

## 修正前RED

LFとbidi制御文字を含む合成missing pathを指定すると、PowerShell 7と
Windows PowerShell 5.1の両方で2 entrypointはexit 1になるが、
raw bidi byteがstderrへ残る。

3 entrypointへ空白だけの `-Path` を明示すると、childへの引数転送時と
本体root選択時に「省略」と扱われ、repo既定rootを検証してexit 0になる。
readinessは成功時も解決済みrootをそのままstdoutへ表示する。

## 受け入れ条件

1. 解決不能または空白だけの明示 `-Path` はexit 1になる。
2. scannerは既存の固定stdout、validator / self-testはentrypoint固有の
   固定UTF-8 stderr 1行だけを返す。
3. 入力pathのLF、bidi、zero-width、line / paragraph separatorや
   解決済みrootを、成功・失敗どちらの出力にも再掲しない。
4. `-Path` を省略した通常実行は従来どおりrepo rootを対象にする。
5. readinessの成功出力はpathを含まない固定文言になる。
6. PowerShell 7とWindows PowerShell 5.1で同じbyte契約を満たす。
7. 正常なreadiness、full self-test、actual scanner、既存のhostile scanner
   root fixtureが退行しない。
8. 実lockや既存の未追跡artifactを変更しない。

## 検証計画

- self-testへ3 entrypointのbounded child fixtureを追加し、missing /
  whitespace rootのraw stdout / stderr byte、exit code、timeout、
  output limitを比較する。
- hostile名の所有junction / symlink経由でreadiness成功経路を実行し、
  path-freeの固定出力を比較する。
- PowerShell 7とWindows PowerShell 5.1でreadiness、full self-test、
  actual scannerを実行する。
- private-marker scan、Semgrep、Gitleaks、UTF-8/BOM/LF/NUL、
  `git diff --check`を実行する。
