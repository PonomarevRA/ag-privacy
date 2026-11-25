# FI/FIO recall preview

[Русский](recall337-preview.ru.md) · [English](recall337-preview.en.md)

This preview adds an optional .NET span ranker for personal names in JSON log messages, including embedded and escaped JSON. It scores two-to-four-token windows using the shape of each word and its neighbors. A full mask covers all annotated name characters. An exact mask also preserves the annotated boundaries.

## Run the example

Run these commands on Linux or macOS from a checkout of the preview tag with .NET SDK 10.0.102 and Python 3.

```sh
demo_dir=$(mktemp -d)
python3 - "$demo_dir/demo.key" <<'PY'
import os
import secrets
import sys

with os.fdopen(os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as key:
    key.write(secrets.token_bytes(32))
PY
dotnet build src/AgPrivacy.Cli -c Release
dotnet src/AgPrivacy.Cli/bin/Release/net10.0/AgPrivacy.Cli.dll stream-log \
  policies/default.json "$demo_dir/demo.key" preview "$demo_dir/journal.ndjson" \
  --log-analysis mixed --person-prose-model models/person-prose.bin \
  --structured-person-model models/person-span-recall337-preview.bin \
  < examples/generated/recall337_before.ndjson
```

The first three example rows demonstrate substitutions, the next two preserve technical text, and the last shows an observed miss. The generated example uses a fixed synthetic key for reproducibility. A new key produces different substitutions. [Synthetic before](../examples/generated/recall337_before.ndjson) · [Generated after](../examples/generated/recall337_after.ndjson)

The preview is selected explicitly through `--structured-person-model`. The existing APNER model format continues to work with that flag. The new weights use the native .NET loader. The ONNX and WebNN guides describe their existing supported weights.

## Evaluation

The training round started from 337 incomplete masks across 22 families. It added paired personal and technical slots and examples with shorter and longer boundaries. The cutoff was chosen on a development split. The frozen synthetic test used separate template and surname families, with 500 personal and 500 technical rows per group.

| Group | Full masks | Exact masks | Technical false masks |
|---|---:|---:|---:|
| Russian, Cyrillic | 435/500 | 435/500 | 0/500 |
| Russian, transliterated | 494/500 | 431/500 | 10/500 |
| English, Cyrillic | 486/500 | 486/500 | 33/500 |
| English, transliterated | 488/500 | 488/500 | 12/500 |
| Total | 1,903/2,000 | 1,840/2,000 | 55/2,000 |

Full masking rose from 87.55% to 95.15% against the previous experimental weights. The preview falls short of the 95% per-group target and the budget of five false masks per 1,000 technical rows. In five local runs at 1,000 offered records/s, median end-to-end p99 was 923.63 ms for the preview and 22.44 ms for the previous weights. The preview processed about 950 records/s. This is a preview for evaluation. [Aggregate measurements](recall337-preview-metrics.json)
