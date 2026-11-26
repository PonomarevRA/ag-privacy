# Lowercase full-name masking preview

[Русский](fio-lowercase-preview.ru.md) · [English](fio-lowercase-preview.en.md)

`person-fio-lowercase-preview.bin` is an experimental checkpoint for the .NET CLI in `stream-log --log-analysis mixed` mode. The main model chooses span boundaries. A second learned decision can restore a rejected three-token lowercase Cyrillic candidate. Training uses synthetic name and technical-phrase pairs with the same surrounding text. Morphological dictionaries were used offline.

## Run the synthetic example

From the project directory with .NET SDK 10.0.102 and Python 3.

```sh
git checkout fi-fio-lowercase-v0.1.0-preview.1
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

| Test set | Complete full-name masks, before → after | Rows falsely masked as `PERSON`, after |
|---|---:|---:|
| Scanpatch regression | 1,107 → 1,107 of 1,298 (85.29%) | 130 of 900 (14.44%) |
| Fresh authored lowercase synthetic test | 1,035 → 1,140 of 1,298 (87.83%) | 3 of 1,298 (0.23%) |
| Fresh Powpowpow23 lowercase test | 405 → 424 of 636 (66.67%) | 183 of 1,298 (14.10%) |

The checkpoint recovered 23 of 66 diagnosed misses. The measured suites recorded zero newly affected `PERSON` rows relative to the preceding filter. Existing false masks remain. Complete recall requires coverage of every non-whitespace character of the annotated name. False-mask denominators count rows without annotated names. The measurements cover full names on the specified cohorts.

- Scanpatch, a frozen regression subset of `data/train-00000-of-00001.parquet`. [Dataset card](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled) · [Pinned file](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled/blob/6af0587dde068d90d8a1080285159c374b46a09b/data/train-00000-of-00001.parquet)
- Powpowpow23, a selected subset of `data/validation.parquet`. In 415 of 636 positive rows, evaluation lowercased the annotated name span and preserved the surrounding text. [Dataset card](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data) · [Pinned file](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data/blob/55acbec07fb04a18455111a34337cb515a7f821e/data/validation.parquet)
- The authored synthetic test uses held-out templates, surname stems and patronymics. [Aggregate metrics and manifest from experiment 56](fio-lowercase-preview-metrics.json). The authored folds are available in the private distribution.

Use the preview for shadow evaluation. External complete recall was 66.67%. p99 at 1,000 rows/s remains unmeasured for this checkpoint.

Model SHA-256 `6cfa72f1bf353e00ca1e934deb44d68e9d7890966377a6fc9c755626a129b5d8`.
