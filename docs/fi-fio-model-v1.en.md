# FI/FIO model v1.0.0

[Русский](fi-fio-model-v1.ru.md) · [English](fi-fio-model-v1.en.md)

`person-fi-fio-v1.bin` is the frozen checkpoint for structured name masking in the native .NET `stream-log Mixed` pipeline. The model scores proposed person spans using word shape and neighboring context. Select it with `--structured-person-model` for JSON messages, including decoded nested and escaped messages.

## Run

From the source checkout on Linux or macOS with .NET SDK 10.0.102 and Python 3.

```sh
git checkout fi-fio-model-v1.0.0
work_dir=$(mktemp -d)
python3 - "$work_dir/demo.key" <<'PY'
import os
import secrets
import sys

with os.fdopen(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as key:
    key.write(secrets.token_bytes(32))
PY
dotnet build src/AgPrivacy.Cli -c Release
dotnet src/AgPrivacy.Cli/bin/Release/net10.0/AgPrivacy.Cli.dll stream-log \
  policies/default.json "$work_dir/demo.key" fi-demo "$work_dir/journal.ndjson" \
  --log-analysis mixed --person-prose-model models/person-prose.bin \
  --structured-person-model models/person-fi-fio-v1.bin \
  < examples/generated/fi_fio_v1_before.ndjson > "$work_dir/masked.ndjson"
```

The example output was generated with a synthetic demonstration key. A different key changes the substitutions. [Input](../examples/generated/fi_fio_v1_before.ndjson) · [Generated output](../examples/generated/fi_fio_v1_after.ndjson)

## Evaluation

| Metric | Previous pilot | v1.0.0 |
|---|---:|---:|
| Complete two-word Russian Cyrillic names, fresh test | 142/275 | 265/275 |
| All complete masks, fresh test | 831/1,200 | 1,172/1,200 |
| Exact spans, fresh test | 753/1,200 | 1,074/1,200 |
| False masks on technical rows, fresh test | 361/1,200 | 241/1,200 |
| False masks on technical rows, previous test | 73/2,000 | 83/2,000 |

These results come from synthetic fixtures with held-out templates and surname families. Eight false masks were removed in the technical-phrase control. Complete recall on the fresh test was 97.67%. The budget of five false masks per 1,000 technical rows remains unmet. This version has no new load measurement. [Aggregate metrics](fi-fio-model-v1-metrics.json)

Model SHA-256 is `490583d0bb2731bb31c8ce2945b8b11c8c58742d662f8b2e99a114f27004ce38`.
