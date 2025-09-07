complete -c neonsec -n '__fish_use_subcommand' -a 'analyze validate doctor'
complete -c neonsec -s -l input -r
complete -c neonsec -l input-format -a 'csv ndjson'
complete -c neonsec -l format -a 'text json ndjson'
complete -c neonsec -l window -r
complete -c neonsec -l portscan -r
complete -c neonsec -l bruteforce -r
complete -c neonsec -l ddos-events -r
complete -c neonsec -l ddos-uniq -r
complete -c neonsec -l anomaly-z -r
complete -c neonsec -l plugin -r
complete -c neonsec -l metrics -r
complete -c neonsec -l sarif -r
complete -c neonsec -l rules -r
complete -c neonsec -l threads -r
complete -c neonsec -l sample -r
complete -c neonsec -l config -r
complete -c neonsec -l pcap -r
complete -c neonsec -l pcap-live -r

complete -c neonsec -l redact
complete -c neonsec -l max-findings -r

complete -c neonsec -l pseudonymize
complete -c neonsec -l pseudonymize-salt -r
complete -c neonsec -l summary

complete -c neonsec -l ts-format -r
complete -c neonsec -l tee -r

complete -c neonsec -l dry-run

complete -c neonsec -l run-id -r
complete -c neonsec -l prolog
complete -c neonsec -l tee-rotate-size -r
complete -c neonsec -l tee-rotate-keep -r
complete -c neonsec -l since -r
complete -c neonsec -l until -r
complete -c neonsec -l only-type -r
complete -c neonsec -l skip-type -r
complete -c neonsec -l only-key -r
complete -c neonsec -l skip-key -r
complete -c neonsec -l only-details -r
complete -c neonsec -l skip-details -r
complete -c neonsec -l csv-header
complete -c neonsec -l index-output -r
complete -c neonsec -l audit-suppressions -r
complete -c neonsec -l flush
complete -c neonsec -l dedupe-window -r
complete -c neonsec -l min-key-count -r
complete -c neonsec -l bucket-summary -r
complete -c neonsec -l bucket-size -r
complete -c neonsec -l redact-patterns -r
complete -c neonsec -l redact-repl -r
complete -c neonsec -l validate-input
complete -c neonsec -l strict
complete -c neonsec -l report-html -r
complete -c neonsec -l artifact-dir -r
complete -c neonsec -l pidfile -r
complete -c neonsec -l sample-rate -r
complete -c neonsec -l sample-seed -r
complete -c neonsec -l split-output -r
complete -c neonsec -l split-by -r
complete -c neonsec -l split-bucket -r
complete -c neonsec -l max-errors -r
complete -c neonsec -l chain
complete -c neonsec -l newline -r
complete -c neonsec -l tee-mode -r
complete -c neonsec -l ip-mask -r
complete -c neonsec -l report-md -r
complete -c neonsec -l group-output -r
complete -c neonsec -l group-by -r
complete -c neonsec -l record-id
complete -c neonsec -l record-id-start -r
complete -c neonsec -l max-output-bytes -r
complete -c neonsec -l utf8-strict
complete -c neonsec -l errors-json -r
complete -c neonsec -l hmac-secret -r
complete -c neonsec -l hmac-env -r
complete -c neonsec -l out -r
complete -c neonsec -l atomic-out
complete -c neonsec -l limit-findings -r
complete -c neonsec -l ts-offset -r
complete -c neonsec -l anomaly-zscore -r
complete -c neonsec -l anomaly-window -r
complete -c neonsec -l anomaly-output -r
complete -c neonsec -l dry-run
complete -c neonsec -l out-digest -r
complete -c neonsec -l log-level -r
complete -c neonsec -l log-format -r
complete -c neonsec -l pii-preset -r
complete -c neonsec -l tee-rotate-interval -r
complete -c neonsec -l shard-count -r
complete -c neonsec -l shard-index -r
complete -c neonsec -l shard-by -r
complete -c neonsec -l details-max -r
complete -c neonsec -l no-ellipsis
complete -c neonsec -l bloom-bits -r
complete -c neonsec -l bloom-hash-count -r
complete -c neonsec -l bloom-key -r
complete -c neonsec -l bloom-state -r
complete -c neonsec -l explain-transform
complete -c neonsec -l input-digest-out -r
complete -c neonsec -l schema -r
complete -c neonsec -l schema-enforce -r
complete -c neonsec -l limit-key-rate -r
complete -c neonsec -l limit-key-window -r
complete -c neonsec -l json-indent -r
complete -c neonsec -l profile-json -r
