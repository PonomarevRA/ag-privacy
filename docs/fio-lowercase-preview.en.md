# Lowercase full-name masking · preview 2

[Русский](fio-lowercase-preview.ru.md) · [English](fio-lowercase-preview.en.md)

`person-fio-lowercase-preview.bin` is an experimental profile for the .NET CLI in `stream-log --log-analysis mixed` mode. An extra learned decision can restore a rejected three-token lowercase Cyrillic span. The first fine-tuning pass started from the MLflow 59 checkpoint. Training used 1,104 same-context pairs and 256 additional quote-context pairs. Morphological dictionaries were used to prepare training data.

## Run the synthetic example

Run from the repository root using .NET SDK 10.0.102 and Python 3.

```sh
git checkout fi-fio-lowercase-v0.1.0-preview.2
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
  policies/default.json "$work_dir/demo.key" fio-preview "$work_dir/journal.ndjson" \
  --log-analysis mixed --person-prose-model models/person-prose.bin \
  --structured-person-model models/person-fio-lowercase-preview.bin \
  < examples/generated/fio_lowercase_preview_before.ndjson > "$work_dir/masked.ndjson"
```

Substitutions depend on the key. [Synthetic input](../examples/generated/fio_lowercase_preview_before.ndjson) · [Example output](../examples/generated/fio_lowercase_preview_after.ndjson)

## Evaluation

| Test set | Complete masks, before → after | False rows, after | New false rows |
|---|---:|---:|---:|
| Historical synthetic | 568 → 582 of 640 | 470 of 2,560 | 0 |
| Fresh external subset | 267 → 268 of 320 | 55 of 400 | 0 |
| Fresh synthetic | 664 → 679 of 768 | 71 of 768 | 0 |
| Scanpatch | 1,107 → 1,107 of 1,298 | 130 of 900 | 0 |

The model removed all 12 targeted false masks. The external subset gained one complete mask overall. On Scanpatch, one additional `PERSON` span fell outside the annotation in a record that already contained annotated names. False-row counts apply to rows without an annotated name. Complete coverage requires masking every non-whitespace character of the annotated name.

The fresh external subset uses unseen groups from the same publisher. For 206 of 320 positive rows, only the annotated full-name interval was lowercased. The synthetic test uses separate templates, surname stems, and negative word forms. [Powpowpow23](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data/blob/55acbec07fb04a18455111a34337cb515a7f821e/data/train.parquet) · [Scanpatch](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled/blob/6af0587dde068d90d8a1080285159c374b46a09b/data/train-00000-of-00001.parquet) · [MLflow 60 aggregate results](fio-lowercase-preview-metrics.json)

Select this profile explicitly for shadow evaluation. p99 at 1,000 records/s remains unmeasured for these weights.

The two release builds matched the benchmark CLI output and replacement journal byte-for-byte across 8,324 records.

Model SHA-256 `ecb1a5f65478a0ed5b49e31fb7b456848a47e4282a561b91a264f8dd68cd7b97`.
