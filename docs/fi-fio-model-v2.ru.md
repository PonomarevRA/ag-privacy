# Модель ФИ и ФИО v2.0.0

[Русский](fi-fio-model-v2.ru.md) · [English](fi-fio-model-v2.en.md)

`person-fi-fio-v2.bin` — встроенная модель распознавания ФИ и ФИО для .NET CLI. Команда `stream-log` без выбора модели использует анализ `Mixed`. При явном выборе `mixed` или `structured` модель также подставляется автоматически, если путь структурной модели не задан. Встроенные веса находятся внутри DLL CLI.

## Синтетический пример

Из корня репозитория с .NET SDK 10.0.102 и Python 3.

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

Подстановки зависят от ключа. [Вход](../examples/generated/fi_fio_v2_before.ndjson) · [Пример результата](../examples/generated/fi_fio_v2_after.ndjson)

Чтобы явно подключить профиль сравнения `preview.2`, передайте `--log-analysis mixed --person-prose-model models/person-prose.bin --structured-person-model models/person-fio-lowercase-preview.bin`. Библиотечные клиенты могут загрузить нужные веса через `PilotSpanSelection.Load` и передать модель в `StreamingPrivacyMasker`. Режим `Text` подходит для конфигурации с одной текстовой моделью. Аргумент модели без выбора режима сохраняет поведение прежнего CLI.

## Результаты

| Набор | Полные маски preview.2 → v2 | Строки с ложным PERSON до → после |
|---|---:|---:|
| Scanpatch | 1 107 → 1 193 из 1 298 (91,91%) | 130 → 103 из 900 |
| Powpowpow23, срез калибровки | 111 → 111 из 126 | 36 → 24 из 240 |
| Отложенные синтетические пары | 482 → 484 из 854 | 28 → 16 |
| Sanorian, технические строки | — | 17 → 16 из 400 |

Версия исправила восемь разобранных ложных строк. На Scanpatch появилась одна новая ложная строка, два новых интервала вне размеченных имён и семь расширений границ ФИО относительно `preview.2`. На прежнем срезе Powpowpow23 и прежней синтетике суммарно появились три новых интервала. Калибровка использовала известные ошибки Scanpatch и Powpowpow23. На отложенных синтетических парах и 400 строках Sanorian новых интервалов вне разметки и расширений границ не наблюдалось. [Scanpatch](https://huggingface.co/datasets/scanpatch/pii-ner-corpus-synthetic-controlled/blob/6af0587dde068d90d8a1080285159c374b46a09b/data/train-00000-of-00001.parquet) · [Powpowpow23](https://huggingface.co/datasets/Powpowpow23/ru-pii-ner-data/blob/55acbec07fb04a18455111a34337cb515a7f821e/data/train.parquet) · [Sanorian](https://huggingface.co/datasets/Sanorian/ru-pii-synthetic) · [Парные метрики](fi-fio-model-v2-metrics.json)

Модель использует оценки окон и локального контекста. Дообучение началось с парного ранжировщика на 1 162 полные маски Scanpatch и включало 800 синтетических пар и ограничения на оценки известных окон. Показатели относятся к этим наборам. Для данных весов p99 при 1 000 записях/с не измерялся.

В обеих сборках вывод по умолчанию и журнал замен побайтно совпали с экспериментальным прогоном на 9 364 записях.

SHA-256 весов `1198c79b828b00c5fa6685ee0090f6f6fcaaf7225aecab961cbf5c0cf07114de`.
