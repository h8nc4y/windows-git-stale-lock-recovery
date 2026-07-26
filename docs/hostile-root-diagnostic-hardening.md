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
- hosted Windows PowerShell 5.1のcold start実測に合わせ、invalid-root childは
  最大45秒、full-readiness childは最大90秒にする。すべてのroot診断fixtureを
  210秒の累積phaseへ入れ、経過時間から次childの残時間を減らし、20秒を
  process-tree / pipe cleanup用に予約する。残時間がなければ固定codeで早期失敗
  する。失敗時はcase名、exit、timeout、output-limit、stream byte数だけを
  表示し、raw pathやraw outputは再掲しない。
- child timeout後のtree termination、process-exit、retry、pipe waitは、
  それぞれに新しい上限を与えず、共有absolute 20-second cleanup deadlineの
  残時間だけを使う。runner startとcleanupの例外は
  `bounded-process-runner-failed`へ畳み、executable pathやplatform exception
  textを反射しない。
- PowerShell 7とWindows PowerShell 5.1でreadiness、full self-test、
  actual scannerを実行する。
- private-marker scan、Semgrep、Gitleaks、UTF-8/BOM/LF/NUL、
  `git diff --check`を実行する。

## Hosted runner実測

CI envelope evidence: job=29m44s; self-test step=28m40s; readiness step=51s;
scanner step=skipped; direct cause=unconfirmed.

[GitHub Actions run 30201021219](https://github.com/h8nc4y/windows-git-stale-lock-recovery/actions/runs/30201021219)
のWindows PowerShell 5.1では、job全体が29分44秒、self-test stepが
28分40秒、readiness stepが約51秒で、後続scanner stepはskippedだった。
新規childを15秒で打ち切った初回runは、root failure 2件とpath-free
readiness成功1件を誤判定した。旧diagnosticはtimeout flagを出して
いなかったため各失敗の直接原因は未確認（direct cause: unconfirmed）だが、
standalone readiness実測とmodule-cache phaseの時間増加はcold-start
deadline不足と整合する。

Windows PowerShell 5.1のjob deadlineは35分（2,100秒）である。attempt 1の
job全体1,784秒に、旧invalid/readiness fixture上限105秒から新累積上限
210秒への増分105秒と、変更していない製品scannerの最大6 child × 15秒 =
90秒を加えると1,979秒（32分59秒）になる。job deadlineまで121秒を残す。
runtime計算とreadinessのstatic gateは、この210秒phase、20秒cleanup reserve、
製品scannerの6-by-15-second契約、1,979秒envelopeを固定する。新diagnosticは
次回失敗時に匿名timeout状態を残す。残り121秒のうち最低120秒は、実scanner
stepのsetup、bounded cleanup、その他job overhead用のreserveとして
runtimeでも検査する。
