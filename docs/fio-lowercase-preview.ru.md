# Маскирование ФИО в нижнем регистре · preview 2

[Русский](fio-lowercase-preview.ru.md) · [English](fio-lowercase-preview.en.md)

`person-fio-lowercase-preview.bin` — экспериментальный профиль .NET CLI для `stream-log --log-analysis mixed`. Дополнительная модель может восстановить отклонённый трёхсловный кириллический интервал в нижнем регистре. Первое дообучение началось с весов MLflow 59. Для обучения использовали 1 104 пары с одинаковым окружением и 256 дополнительных пар для фраз в кавычках. Морфологические словари использовались при подготовке корпуса.

## Запуск на синтетическом примере

Из корня проекта с .NET SDK 10.0.102 и Python 3.

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

Подстановки зависят от ключа. [Вход](../examples/generated/fio_lowercase_preview_before.ndjson) · [Пример результата](../examples/generated/fio_lowercase_preview_after.ndjson)

## Результаты

| Набор | Полные маски до → после | Ложные строки после | Новые ложные строки |
|---|---:|---:|---:|
| Прежняя синтетика | 568 → 582 из 640 | 470 из 2 560 | 0 |
| Свежий внешний срез | 267 → 268 из 320 | 55 из 400 | 0 |
| Свежая синтетика | 664 → 679 из 768 | 71 из 768 | 0 |
| Scanpatch | 1 107 → 1 107 из 1 298 | 130 из 900 | 0 |

Устранены 12 из 12 целевых ложных масок. На внешнем срезе прирост составляет один пример. На Scanpatch появился один дополнительный интервал `PERSON` вне разметки в записи с уже размеченными именами. Счётчик ложных строк учитывает строки без размеченных имён. Полная маска закрывает все непробельные символы размеченного ФИО.

Независимый внешний срез использует другие группы того же корпуса. В 206 из 320 положительных строк только размеченный интервал приведён к нижнему регистру. Синтетический набор имеет отдельные шаблоны, фамильные основы и отрицательные словоформы. [Внешний корпус Powpowpow23](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data/blob/55acbec07fb04a18455111a34337cb515a7f821e/data/train.parquet) · [Scanpatch](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled/blob/6af0587dde068d90d8a1080285159c374b46a09b/data/train-00000-of-00001.parquet) · [Сводка MLflow 60](fio-lowercase-preview-metrics.json)

Профиль предназначен для теневой оценки с явным подключением в CLI. Для этих весов p99 при 1 000 записей/с не измерялся.

В двух сборках сверили вывод CLI и журнал замен на 8 324 записях. Они побайтно совпали с результатами экспериментального прогона.

SHA-256 весов `ecb1a5f65478a0ed5b49e31fb7b456848a47e4282a561b91a264f8dd68cd7b97`.
