# Модель ФИ и ФИО v1.0.0

[Русский](fi-fio-model-v1.ru.md) · [English](fi-fio-model-v1.en.md)

`person-fi-fio-v1.bin` — зафиксированные веса для структурной ветки `stream-log Mixed`. Модель повторно оценивает интервалы ФИО по форме слов и ближайшему контексту. Веса рассчитаны на нативный .NET CLI. Параметр `--structured-person-model` выбирает модель для полей JSON, включая декодированные вложенные и экранированные сообщения.

## Запуск

Из корня репозитория на Linux или macOS с .NET SDK 10.0.102 и Python 3.

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

Файлы примеров показывают фактический вывод с демонстрационным ключом. При новом ключе изменятся подстановки. [Вход](../examples/generated/fi_fio_v1_before.ndjson) · [Результат](../examples/generated/fi_fio_v1_after.ndjson)

## Проверка качества

| Показатель | Прежний пилот | v1.0.0 |
|---|---:|---:|
| Двухсловные ФИ RU × кириллица, свежий тест | 142/275 | 265/275 |
| Все полные маски, свежий тест | 831/1 200 | 1 172/1 200 |
| Точные границы, свежий тест | 753/1 200 | 1 074/1 200 |
| Технические ложные маски, свежий тест | 361/1 200 | 241/1 200 |
| Технические ложные маски, прежний тест | 73/2 000 | 83/2 000 |

Результаты получены на синтетических данных с отдельными семействами фамильных основ и шаблонов. В контроле технических фраз устранены восемь ложных масок. Полнота на свежем тесте — 97,67%. Бюджет до пяти ложных масок на 1 000 технических строк пока превышен. Новый контроль нагрузки для этого релиза не проводился. [Агрегированные метрики](fi-fio-model-v1-metrics.json)

SHA-256 весов — `490583d0bb2731bb31c8ce2945b8b11c8c58742d662f8b2e99a114f27004ce38`.
