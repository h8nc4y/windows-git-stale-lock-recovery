# 公開報告のprivacy boundary

## 区分

Class M（安全ガイダンスと機械検証の小規模変更）。

## 目的

stale lockの5点確認では、ローカル診断として実パス、mtime、実行中
`git.exe` のcommand lineを確認する必要がある。一方、それらをpublic issue、
PR、外部チャットへそのまま転記すると、private repository名、内部絶対パス、
credential-bearing remote URLなどを漏らす可能性がある。

診断に必要なlocal evidenceと、外部へ共有できるsanitized summaryを明確に分離し、
削除判断の精度を落とさずに公開境界をfail closed化する。

## 現在のgap

- `SKILL.md` のReporting節はfull pathとprocess command lineの記録を求めるが、
  local/private recordとpublic/external reportを区別していない。
- bulk exampleは削除対象のfull pathを表示する。これはlocal auditには有用だが、
  公開報告へコピーしてよい出力ではない。
- walkthroughのtemplateはplaceholderを使っているものの、canonical skill側に
  このsanitization contractが固定されていない。

## 影響

- lock削除の5条件、単一lockだけを対象にする制約、3回停止規定は変更しない。
- 実lock、実ユーザーrepository、実processの作成・保持・削除は行わない。
- public/external reportではrepository/pathをplaceholderへ置換し、processは
  PIDやraw command lineではなくread-only/index-writingの分類だけを共有する。
- protected materialを含むraw evidenceが必要な場合は公開せず、local/privateに
  保持してprivate security channelを使う。

## 変更対象

- canonical `SKILL.md` と `docs/SKILL.ja.md`
- README、SECURITY、single-lock/checklist examples
- `scripts/validate-oss-readiness.ps1` のsource contract
- CHANGELOG

## 受け入れ条件

1. local/private evidenceとpublic/external summaryの二層が両言語で一致する。
2. public側は`<repo>`等のplaceholderとprocess command classだけを許可し、
   raw command line、internal absolute path、credential-bearing outputを禁止する。
3. bulk cleanupのfull-path listingはlocal/private audit用と明記する。
4. validatorがcanonical skill、Japanese skill、README、SECURITY、walkthroughの
   reporting boundaryを検査し、文言欠落をfail closedで拒否する。
5. full readiness、scanner self-test、private-marker scan、whitespace checkが通る。

## 検証計画

1. validatorへ新contractを先に追加し、現行docsに対してREDを確認する。
2. canonical docsとexamplesを最小変更してGREENへする。
3. PowerShell 7 / Windows PowerShell 5.1のreadinessを実行する。
4. scanner self-test、repository private-marker scan、Gitleaks、Semgrep、
   `git diff --check`を実行する。
5. exact staged freezeを独立reviewし、clearance後だけcommit/push/PRへ進む。

## 実測結果

- 新しいreporting contractを先に追加した時点では7件不足としてREDになった。
- `validate-oss-readiness.ps1`はPowerShell 7とWindows PowerShell 5.1で成功した。
- `test-scan-private-markers.ps1`はPowerShell 7とWindows PowerShell 5.1で成功した。
- repository private-marker scanは両PowerShell hostで成功した。
- Gitleaksは4 commits、約412.51 KBを検査し、leak 0件だった。
- Semgrep `p/secrets`は4 files、36 rulesでfinding 0件だった。
- `git diff --check`は成功した。
- 最初の独立reviewは、旧report指示の残存と禁止文反転を許すvalidatorを
  P2として各1件検出した。旧指示をlocal/private境界へ統一し、安全な定型文と
  in-memory negative mutationをvalidatorへ追加した。
- 再reviewはchecklistだけkeyword順検査が残るP2を検出した。同じexact semantic
  contractへ統一し、raw evidence公開と`only`反転のnegative mutationを追加した。
- GitHub Actions、PR、merge後のdefault branchはこの時点では未確認。
