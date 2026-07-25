# ModuleAnalysisCache 隔離メンテナンス記録

## 区分

Class M（検証スクリプトの副作用修正）。

## 目的

Windows PowerShell 5.1 の scanner / self-test が成功しても、相対
`PSModuleAnalysisCachePath` を使った場合に実行 cwd へ
`Microsoft/Windows/PowerShell/ModuleAnalysisCache` を残さない。

## 影響

- `scan-private-markers.ps1`、`test-scan-private-markers.ps1`、
  `validate-oss-readiness.ps1` は、cmdlet / module discovery より前の
  .NET-only bootstrap phase で現在の親 host の cache を null device へ向ける。
- 実処理は、同じ PowerShell executable を一度だけ再起動した child が行う。
- child は起動前から Windows の `NUL` または非 Windows の `/dev/null` を
  `PSModuleAnalysisCachePath` として継承する。
- cache 用の temp file / directory と cleanup 処理は作らない。
- native Git child へ cache path、隔離 marker、旧 owner 値を渡さない。
- `.gitignore` では隠さず、再発時は untracked artifact として検出できる。

## 設計上の安全条件

1. 親 entrypoint は cmdlet / module discovery より前に null sink を設定する。
2. entrypoint は上書き前の ambient marker/path pair を capture する。child は
   launcher marker と platform 固有 sink の両方が元から一致する場合だけ
   bootstrap 済みと判定し、marker 単独では再起動を省略しない。
3. host executable は通常の `powershell[.exe]` / `pwsh[.exe]` だけに限定する。
4. `ProcessStartInfo` は stdin / stdout / stderr を redirect せず、親の OS handle を
   そのまま継承する。PowerShell text pipeline で再 encoding しない。
5. launcher は child の完了を待ち、exit code をそのまま返す。
6. helper の欠落・load 失敗・host 解決失敗は、生 path や例外を出さず固定 code で
   fail closed にする。
7. filesystem cache を作らないため、ambient `TEMP` / `TMP`、junction / symlink、
   cleanup の validate-to-delete 競合を cache 境界から除外する。
8. hosted Windows PowerShell 5.1 の cold start を許容する primary probe は120秒、
   missing-helper は各10秒、明示 target scanner は各40秒の個別上限を持つ。
   `TimedOut = $true` の合成結果を同じ判定関数へ通し、上限拡張が再帰 hang を
   成功扱いしないことを固定する。

Microsoft の仕様どおり、確実な起動前設定は新しい child process で行う。通常の
利用経路は README にある `-NoProfile -File` である。profile または長時間動作中の
埋込み host が script より前に module discovery を終えている場合、その既存 host の
過去の状態までは遡及して変更できないため、新しい CLI process から実行する。

## 回帰 fixture

- marker 単独 + 相対 cache path と所有 temp cwd から未隔離 probe host を起動する。
- 親・child・処理後の PID、host path、sink、引数を記録し、同一 host で一度だけ
  再起動したことを確認する。
- stdout は `0..255`、stderr は `255..0` の raw bytes、child は exit 23 とし、
  stream 分離・全 byte・exit code の完全一致を確認する。
- 空文字、空白、引用符、末尾 backslash、semicolon、`$` を含む引数を確認する。
- helper の無い directory へ3 entrypointを複製し、本体開始前の固定失敗を確認する。
- 明示 scan target 自体を `TEMP` / `TMP` / `TMPDIR` にした場合と、その target を
  指す Windows junction / POSIX symlink の場合に cache artifact が無いことを確認する。
- primary probe の実process結果と合成 `TimedOut = $true` を同じ契約関数へ渡し、
  timeoutはraw streamやexitが一致していても必ず不合格にする。
- `.gitignore` による除外は追加せず、呼出元 cwd の `Microsoft` tree 不在を確認する。

## 検証記録

- 変更前の Windows PowerShell 5.1 full self-test:
  136.9秒、exit 0、全 phase 完了後に temp clone 直下の artifact を再現。
- 修正後の Windows PowerShell 5.1 full self-test:
  marker-only + 相対 cache + 所有 cwd、149.3秒、exit 0、stderr 0、
  全11 phase PASS、cwd artifact 0。
- hosted probe deadline修正後の Windows PowerShell 5.1 full self-test:
  131.8秒、全 phase PASS、stderr 0、cwd artifact 0。監視再接続後の
  OS exit code 直接値だけは未取得。
- 修正後の PowerShell 7 full self-test:
  marker-only + 相対 cache + 所有 cwd、290.3秒、exit 0、stderr 0、
  全11 phase PASS、cwd artifact 0。
- hosted probe deadline修正後の PowerShell 7 full self-test:
  287.2秒、exit 0、stderr 0、全 phase PASS、cwd artifact 0。
- PowerShell 7 / Windows PowerShell 5.1 readiness: ともに PASS。
- Linux PowerShell 7.5.0:
  read-only bind mount、`--network none`、`/tmp` tmpfs、60.7秒、exit 0、
  stderr 0、readiness / full self-test / actual scan / staged diff check PASS。
- hosted probe deadline修正後の Linux PowerShell 7.5:
  source indexとtreeが一致する実体 `.git` fixtureをread-only bindし、
  `--network none`、read-only rootfs、`/tmp` tmpfsで56.7秒、exit 0。
  readiness / full self-test / actual scan / staged diff check PASS。
- Gitleaks 8.30.1:
  timeout follow-up差分を含む履歴3 commitsでfindings 0、exit 0。
- Semgrep 1.165.0 `p/default`:
  82 rules、23 files、findings 0、errors 0、exit 0。
- PR run `30150242288`: PowerShell 7 / Ubuntu はPASS。Windows PowerShell
  5.1 は全 phaseを完了した後、primary probeの30秒上限によりraw streamと
  parent/child reportの2 assertionがFAIL。上限をbounded 120秒へ変更し、
  redacted診断と合成timeout failure fixtureを追加した。修正後CIは未確認。

## 出典

- [Microsoft Learn: about Windows PowerShell 5.1](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_windows_powershell_5.1?view=powershell-5.1)
- [Microsoft Learn: about Environment Variables](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
