# Предварительный выпуск для ФИО в нижнем регистре

[Русский](fio-lowercase-preview.ru.md) · [English](fio-lowercase-preview.en.md)

`person-fio-lowercase-preview.bin` содержит экспериментальные веса для .NET CLI в режиме `stream-log --log-analysis mixed`. Основная модель выбирает границы ФИО. Дополнительная линейная модель может вернуть ранее отклонённый трёхсловный кандидат с кириллицей в нижнем регистре. Обучение использует синтетические пары ФИО и технических фраз с одинаковым окружением. Морфологические словари использованы офлайн.

## Запуск синтетического примера

Из каталога проекта с .NET SDK 10.0.102 и Python 3.

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

Значения подстановки зависят от ключа. [Синтетический вход](../examples/generated/fio_lowercase_preview_before.ndjson) · [Пример вывода](../examples/generated/fio_lowercase_preview_after.ndjson)

## Результаты

| Набор | Полные маски ФИО до → после | Ложные строки `PERSON` после |
|---|---:|---:|
| Scanpatch, повторный прогон | 1 107 → 1 107 из 1 298 (85,29%) | 130 из 900 (14,44%) |
| Свежая синтетика, нижний регистр | 1 035 → 1 140 из 1 298 (87,83%) | 3 из 1 298 (0,23%) |
| Powpowpow23, нижний регистр | 405 → 424 из 636 (66,67%) | 183 из 1 298 (14,10%) |

Относительно предыдущего фильтра восстановлено 23 из 66 разобранных пропусков. На этих прогонах наблюдалось 0 новых ложных строк `PERSON` при сохранении ранее существовавших ошибок. Полная маска покрывает все непробельные символы размеченного ФИО. Доля ложных строк рассчитана на строках без размеченного имени. Результаты относятся к ФИО и выбранным наборам.

- Scanpatch, зафиксированный тестовый срез из `data/train-00000-of-00001.parquet`. [Карточка датасета](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled) · [Зафиксированный файл](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled/blob/6af0587dde068d90d8a1080285159c374b46a09b/data/train-00000-of-00001.parquet)
- Powpowpow23, подвыборка из `data/validation.parquet`. В 415 из 636 положительных строк только размеченный интервал ФИО приведён к нижнему регистру. [Карточка датасета](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data) · [Зафиксированный файл](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data/blob/55acbec07fb04a18455111a34337cb515a7f821e/data/validation.parquet)
- Свежая авторская синтетика использует отдельные шаблоны, основы фамилий и отчества. Манифест и агрегаты доступны в [результатах эксперимента 56](fio-lowercase-preview-metrics.json). Авторские фолды входят в приватную комплектацию.

Версия предназначена для теневого пилота. Внешнее покрытие составляет 66,67%, а p99 при 1 000 записей/с для этих весов ещё не измерен.

SHA-256 весов `6cfa72f1bf353e00ca1e934deb44d68e9d7890966377a6fc9c755626a129b5d8`.
