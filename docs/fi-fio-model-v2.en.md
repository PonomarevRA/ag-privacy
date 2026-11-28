# FI/FIO model v2.0.0

[Русский](fi-fio-model-v2.ru.md) · [English](fi-fio-model-v2.en.md)

`person-fi-fio-v2.bin` is the bundled full-name model for the .NET CLI. `stream-log` selects `Mixed` analysis by default. Explicit `mixed` and `structured` modes also use the bundled profile when no structured model path is supplied. The weights live inside the CLI assembly.

## Synthetic example

Run from the repository root using .NET SDK 10.0.102 and Python 3.

```sh
git checkout fi-fio-model-v2.0.0
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
  policies/default.json "$work_dir/demo.key" fio-v2 "$work_dir/journal.ndjson" \
  < examples/generated/fi_fio_v2_before.ndjson > "$work_dir/masked.ndjson"
```

Substitutions depend on the key. [Input](../examples/generated/fi_fio_v2_before.ndjson) · [Example output](../examples/generated/fi_fio_v2_after.ndjson)

To select the `preview.2` comparison profile, pass `--log-analysis mixed --person-prose-model models/person-prose.bin --structured-person-model models/person-fio-lowercase-preview.bin`. Library consumers can load weights with `PilotSpanSelection.Load` and pass the model to `StreamingPrivacyMasker`. Explicit `Text` mode is available for configurations that use a prose detector. Supplying a person model without an analysis mode keeps the legacy CLI behavior.

## Evaluation

| Dataset | Complete masks, preview.2 → v2 | False PERSON rows, before → after |
|---|---:|---:|
| Scanpatch | 1,107 → 1,193 of 1,298 (91.91%) | 130 → 103 of 900 |
| Powpowpow23 calibration subset | 111 → 111 of 126 | 36 → 24 of 240 |
| Held-out synthetic pairs | 482 → 484 of 854 | 28 → 16 |
| Sanorian technical rows | — | 17 → 16 of 400 |

The new checkpoint resolved all eight audited false rows. Relative to `preview.2`, Scanpatch gained one false row, two spans outside annotated names, and seven boundary extensions. Three additional spans appeared on the earlier Powpowpow23 and synthetic suites combined. Calibration used known Scanpatch and Powpowpow23 cases. The held-out synthetic pairs and Sanorian controls introduced no unmatched PERSON spans or boundary extensions. [Scanpatch](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled/blob/6af0587dde068d90d8a1080285159c374b46a09b/data/train-00000-of-00001.parquet) · [Powpowpow23](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data/blob/55acbec07fb04a18455111a34337cb515a7f821e/data/train.parquet) · [Sanorian](https://huggingface.co/datasets/Sanorian/ru-pii-synthetic) · [Paired metrics](fi-fio-model-v2-metrics.json)

The pipeline scores candidate windows with nearby context. Training started from the pairwise ranker that produced 1,162 complete masks on Scanpatch and added 800 synthetic pairs and score constraints on diagnosed windows. Results apply to the listed benchmarks. p99 at 1,000 records/s remains unmeasured for this checkpoint.

The bundled default in both release builds matched the benchmark output and replacement journal byte-for-byte across 9,364 records.

Model SHA-256 `1198c79b828b00c5fa6685ee0090f6f6fcaaf7225aecab961cbf5c0cf07114de`.
