# Windows の stale git lock からの安全な復旧

これはリポジトリルートの [SKILL.md](../SKILL.md)（英語・正典）の日本語版です。内容が
食い違う場合は英語版を正とします。

Windows で stale な `.git/index.lock`（または `.git/config.lock`）から、誰の作業も
壊さずに復旧するための手順です。中核は、唯一の破壊操作（lock ファイルの削除）の前に
全部そろっていなければならない5点の安全チェックと、TOCTOU を意識した一括掃除、
`--no-optional-locks` による予防です。

## いつ使うか

- `git add` / `git switch` / `git commit` / `git merge` が
  `Unable to create '.git/index.lock': File exists` で失敗する。
- `gh pr merge` は GitHub 側で成功したのに、ローカル更新だけ `index.lock` で失敗・
  警告が出る（無害な後処理として扱う）。
- `git status` が `warning: unable to unlink '.git/index.lock'` を残す。
- lock ファイルが 0 bytes で、mtime が現行作業より古い。

根本原因: sandbox 化された git プロセス（例: Codex アプリ等のエージェントアプリが
短命に走らせる `git status --porcelain` や config/remote 読み取り）が lock を作った
後、sandbox 内で unlink できずに終了して 0-byte lock が残る。**同時作業ではない**
ので、「他の git プロセスが動いている」と誤認して待ち続けない。`.git/config.lock`
も同型として同じ手順を適用する（誠実性の注記: この skill の元になった実測記録は
大半が `index.lock` であり、`config.lock` の発生実測は未確認）。

## 手順

1. **読み取り専用で現状確認**（lock を新たに作らない方法を使う）。
   - PowerShell: `git -C <repo> --no-optional-locks status`
   - Git Bash / POSIX シェル: `GIT_OPTIONAL_LOCKS=0 git -C <repo> status`
2. **動作中の git プロセスとコマンドラインを確認**（PowerShell）。

   ```powershell
   Get-CimInstance Win32_Process -Filter "Name='git.exe'" | Select-Object ProcessId,CommandLine
   ```

   エージェントアプリ（例: Codex アプリ）由来の短命 `git status` が頻出することが
   ある。index を書く操作（add / commit / merge / checkout 等）のコマンドラインが
   **無い**ことを確認する。raw process一覧はlocal/private evidenceとして扱う。
   command lineにはprivate pathやcredential-bearing remote URLが含まれ得るため、
   public/external reportへraw command lineを貼らない。
3. **lock ファイルの実体を確認**。
   - PowerShell: `Get-Item -LiteralPath '<repo>\.git\index.lock' | Select-Object FullName,Length,LastWriteTime`
   - Git Bash: `ls -l <repo>/.git/index.lock`
4. **lock パスが意図した repo 配下か確認**。
   `git -C <repo> rev-parse --absolute-git-dir` の直下にある lock だけを対象にする。
5. **排他 open テスト**（PowerShell）。例外なく開ければ他プロセスは保持していない。

   ```powershell
   $f = [IO.File]::Open('<repo>\.git\index.lock','Open','Read','None'); $f.Close()
   ```

   Git Bash には Windows の排他 open に相当する素の POSIX コマンドがないため、
   この1段だけ PowerShell を呼び出す:

   ```bash
   powershell.exe -NoProfile -Command "[IO.File]::Open('<repo>\.git\index.lock','Open','Read','None').Close()"
   ```

   この呼び出しの中の `<repo>` だけは Windows 形式で置換する — /c/projects/repo
   ではなく C:\projects\repo のように書く。.NET は Git Bash 形式のパスを解釈
   せず、引用符で囲んだ `-Command` 文字列の中では MSYS2 のパス変換も働かない
   ため。

6. **【破壊操作】lock 削除** — 「安全条件」の5点チェックを**すべて**満たしたとき
   だけ、当該 lock ファイル1つのみ削除する。
   - PowerShell: `Remove-Item -LiteralPath '<repo>\.git\index.lock' -Confirm:$false`
   - Git Bash: `rm <repo>/.git/index.lock`
7. **ブロックされていた git 操作を再実行**。同一 repo の git index 操作は直列化
   する — 同一 repo での `git add` と `git status` の並行実行で lock 競合が再発した
   実測あり（field-tested）。
8. **`gh pr merge` 後に失敗した場合**: GitHub 側の merge は成功していることが多い。
   先に PR 状態を確認してから lock を処理し、ローカルを整合させる。**必ず現在
   ブランチを確認してからデフォルトブランチに切り替えて fast-forward する** —
   この状況では feature ブランチに残っていることが多く、feature ブランチのまま
   実行すると（`--ff-only` なので履歴破壊はしないが）feature ブランチの ref を
   黙って origin のデフォルトブランチへ進めてしまう。デフォルトブランチ名は repo
   により異なる（main / master 等）ので決め打ちしない。

   ```powershell
   gh pr view <pr-number> --json state,mergedAt
   # merge済みなら: 5点チェック → lock削除 → ローカル整合
   git branch --show-current          # 現在ブランチを確認（feature に残っていることが多い）
   gh repo view --json defaultBranchRef -q .defaultBranchRef.name   # デフォルトブランチ名を確認
   git switch <default>
   git fetch --prune
   git merge --ff-only origin/<default>
   ```

   これらのコマンドは POSIX シェルでもそのまま動く。
9. **複数 repo の一括掃除**。誠実性の注記: この skill の元になった実績は
   **repo ごとの個別削除**（各 repo で path 検証＋排他 open 確認後に削除）であり、
   下記の一括コマンド自体の実行実績は未確認。使う場合の例（PowerShell）:

   ```powershell
   # 例（この一括コマンド自体の実行実績は未確認。実績は repo ごとの個別削除）
   # このblockのpath付き出力はすべてlocal/private audit用。外部共有前にsanitizeする
   Get-CimInstance Win32_Process -Filter "Name='git.exe'"   # 出力なし＝この時点で git 不在（開始時スナップショット）
   Get-ChildItem <workspace-root>\*\.git\index.lock -ErrorAction SilentlyContinue |
     Where-Object { $_.Length -eq 0 -and $_.LastWriteTime -lt (Get-Date).AddMinutes(-10) } |
     ForEach-Object {
       $lock = $_
       try {
         # 条件5: lock 1件ごとの排他 open テスト。開けない lock は他プロセス保持とみなしスキップ
         $f = [IO.File]::Open($lock.FullName,'Open','Read','None'); $f.Close()
         Remove-Item -LiteralPath $lock.FullName -Confirm:$false
         $lock.FullName   # 削除したlockをlocal/private audit用にだけ出力
       } catch {
         Write-Warning "Skipped (exclusive open or delete failed; no forced delete, no retry): $($lock.FullName)"
       }
     }
   ```

   - `<workspace-root>` は自分の環境の repo 親ディレクトリに置換する（Windows
     の例: C:\projects など）。
   - 開始時の `git.exe` 確認はスナップショットにすぎず、掃除中に新しい git が走る
     隙（TOCTOU）を塞げない。**mtime フィルタ（現行作業より古い lock だけを対象）
     が実質のガード**であり、掃除中に新しい git が作った lock は mtime が新しい
     ため対象外になる。`-10` 分は目安であり実測の固定値ではない（未確認）。本質は
     「現行作業より前の lock だけを消す」こと。
   - 一括掃除でも5点チェックは lock 1件ごとに適用する。条件2（意図した repo 配下）
     は glob パターン `<workspace-root>\*\.git\index.lock`（repo 直下の `.git` のみ
     に一致）で代替しているので、削除した lock のフルパスをlocal audit recordへ
     列挙し、代替した旨を明記する。
   - 一括掃除のfull-path outputはlocal/private audit用である。public/externalへ
     共有する前に、各pathを`<repo>/.git/index.lock`のようなplaceholderへ置換する。

## 安全条件

削除（唯一の破壊操作）は、次の**5点すべて**を満たしたときだけ実行する。

1. `git.exe` プロセスが動いていない（動いていても index を書く操作のコマンド
   ラインが無い）
2. lock のパスが意図した repo の `.git` 配下である
3. ファイルが 0 bytes である
4. mtime が古い（現行の自分の操作より前。具体的な閾値の実測固定値は未確認）
5. 排他 open が成功する

停止・禁止条件:

- 5点のうち1つでも欠けたら削除しない。上限付きで再確認する（例: ブロックされて
  いた git 操作の再試行は2〜3回まで、都度5点チェックをやり直す。無期限待機・
  foreground sleep・「自然解消を待つ」放置は行わない）。同一失敗クラスが3回試して
  も改善しなければ停止し、下記のsanitized boundaryで状況を報告する。
- 削除対象は当該 lock ファイル**のみ**。`.git/index` / `.git/config` 本体やその他
  の `.git` 内容には触れない。
- プロセスの強制終了・sandbox の解除（unsandbox 化）はこの skill の範囲外として
  実施しない。kill が必要に見えても人間の判断待ちで停止せず、状況（プロセス ID・
  コマンドライン・lock のパス/サイズ/mtime）をlocal/private evidenceへ残したうえ
  で、直列化や上限付き再確認など kill 不要の代替で継続する。3回試しても改善しな
  ければ停止し、下記のsanitized boundaryで報告する。
- 一括掃除でも5点チェックは lock 1件ごとに適用する。条件1のプロセス確認は開始時
  スナップショットにすぎないため、mtime フィルタと lock ごとの排他 open（条件5）
  を必須とし、排他 open や `Remove-Item` に失敗した lock はスキップする
  （強制削除・リトライ禁止）。実pathはlocalに保持し、報告ではsanitized placeholder
  と理由だけを記載する。5点チェックの一部をフィルタで代替した場合は、代替した
  条件を報告に明記する。
- 0 bytes でない lock は原則削除しない。index と同サイズの lock が完了済み操作後
  に残った実測はある（field-tested）が、その場合も残り4条件と直前操作の完了を
  確認できたときのみ削除する。
- 同じ失敗が3回改善しなければ停止し、実lock path・サイズ・mtime・プロセス確認
  結果はlocal/private evidenceへ保持する。public/externalの停止報告では、下記の
  sanitized lock placeholderとprocess command classを使う。

## 完了チェック

- ブロックされていた git 操作（add / switch / commit / merge / ローカル
  fast-forward）が成功した。
- `git --no-optional-locks status` が期待どおり（警告なし・想定の差分のみ）。
- 対象 repo に新しい lock が残っていない。
- （merge 後処理の場合）デフォルトブランチ（main / master 等、repo により異なる）
  のローカルが `origin/<デフォルトブランチ>` と一致している。

## 報告

- **local/private evidence:** 削除判断と保護された監査記録のために、対象repo、
  実lock path、サイズ、mtime、raw process一覧を保持する。credential-bearing
  outputをticketやchatへ転記しない。
- **public/external report:** repoとlock pathは
  `<repo>/.git/index.lock`のようなplaceholderへ置換する。process確認は
  `no git.exe` / `read-only` / `index-writing`のcommand classだけを記載し、
  PID、raw command line、remote URL、environment valueは省く。
- 5点確認の各結果、削除・skipしたlockのplaceholderと理由、filterで代替した条件、
  再実行したgit操作の結果を記載する。
- security調査でprotected raw evidenceが必要ならpublic channelへ出さず、
  repositoryのprivate security reportingを使う。
- 確認できなかった項目は「未確認」と明記する。実測していない値を断定しない。

## 予防

- エージェントの読み取り専用チェックは常に `git --no-optional-locks status`
  （または `GIT_OPTIONAL_LOCKS=0`）を使い、optional lock 自体を作らない。
- 同一 repo での git index 操作を並行させない（直列化する）。
- `gh pr merge` 後の `index.lock` 警告は「sandbox 化 git が cleanup できなかった
  無害な後処理」として扱い、同時作業と誤認しない。

## 出典（Provenance）

この skill は、sandbox 化されたエージェントアプリが短命の git コマンドを走らせる
Windows 開発機での、実運用の反復から蒸留したものです。後述の3点を除き、上記の
ルールは観測された失敗か検証済みの復旧に遡れます（推測ではありません）。
「field-tested / 実測あり」は、実際に踏んで回避策が機能した挙動を指します。次の
3点は設計由来で実運用未検証のため、明示的にマーカーを残しています。

- `.git/config.lock`: 発生の直接観測はない。`index.lock` と同型の失敗として含めた
  （未確認）。
- 手順9の一括掃除コマンド: 実測記録は repo ごとの個別削除（path 検証＋排他 open
  →削除）であり、一括形そのものの実行実績はない（未確認）。
- mtime 閾値: 実測の固定値はない。`-10` 分は目安であり、本質は「現行作業より前の
  lock だけを対象にする」こと（未確認）。
