# Запуск моделей ФИО через ONNX

`AgPrivacy.Onnx` подключает ONNX Runtime CPU к интерфейсу `IPersonDetector`. Подготовлены `models/person-default.onnx` и `models/person-prose.onnx`. Их можно передать в `PrivacyEngine` и `StreamingPrivacyMasker`.

## Запуск примера

Нужен .NET SDK, указанный в `global.json`. Команды выполняются из корня репозитория. Следующая команда читает UTF-8 NDJSON из stdin и пишет замаскированные записи в stdout.

```sh
dotnet run --project examples/Onnx -c Release -- \
  models/person-default.onnx models/person-prose.onnx \
  < examples/Onnx/input.ndjson > masked.ndjson
```

В `examples/Onnx/input.ndjson` находятся синтетические записи. Одна из них выглядит так.

```json
{"trace.id":"demo-trace-01","message":"Контакт: Алина Зорничева; email=sample.person@example.test","status":"ok"}
```

Пример создаёт случайный ключ для одного запуска. Для устойчивых подстановок между запусками приложение передаёт собственный защищённый ключ и область.

## Подключение в .NET

```sh
dotnet add /path/to/your-app reference /path/to/ag-privacy/src/AgPrivacy.Onnx/AgPrivacy.Onnx.csproj
```

```csharp
using System.Security.Cryptography;
using AgPrivacy;

using var model = OnnxPersonDetector.Load(File.ReadAllBytes("models/person-default.onnx"));
using var prose = OnnxPersonDetector.Load(File.ReadAllBytes("models/person-prose.onnx"));
var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
byte[] key = RandomNumberGenerator.GetBytes(32);
using var aliases = new Pseudonymizer(key, "my-application");
CryptographicOperations.ZeroMemory(key);

var stream = new StreamingPrivacyMasker(policy, aliases, model, null, null, null, prose);
await stream.MaskAsync(Console.OpenStandardInput(), Console.OpenStandardOutput());
```

Один детектор хранит сессию ONNX Runtime. Освобождайте его через `Dispose` после завершения обработки. Вызовы одного экземпляра синхронизированы вместе с освобождением сессии. Создавать модель заново для каждого сообщения не требуется.

Проект `AgPrivacy.Onnx` имеет зависимость `Microsoft.ML.OnnxRuntime` версии `1.27.0`. При установке NuGet выбирает нативные библиотеки для платформы приложения. Обычный пакет `AgPrivacy.Core` используется самостоятельно. ONNX-пакет можно собрать для локальной установки.

```sh
dotnet pack src/AgPrivacy.Core -c Release -o ./packages
dotnet pack src/AgPrivacy.Onnx -c Release -o ./packages
dotnet add /path/to/your-app package AgPrivacy.Onnx --version 0.2.0 --source ./packages
```

## Экспорт своих дообученных весов

Экспортёр принимает формат `APNER001`, который создаёт `AgPrivacy.Train`. Нужен Python 3.10 или новее.

```sh
python3 -m venv .onnx-venv
.onnx-venv/bin/python -m pip install -r tools/onnx/requirements.txt
.onnx-venv/bin/python tools/onnx/export_person.py \
  models/person-prose.bin models/person-prose.onnx
```

На Windows Python этого окружения находится в `.onnx-venv\Scripts\python.exe`. После дообучения экспорт выполняется повторно. `SourceModelVersion` возвращает SHA-256 исходных весов `.bin`, а `Version` — SHA-256 загруженного `.onnx`.

## Что выполняется в графе

Вход `features` имеет тип int64 и размер `[tokens, 3, 12]`. Для каждого токена подготавливаются три набора признаков, соответствующие трём возможным предыдущим BIO-меткам. Используются те же токенизатор и хэширование, что в `MicroPersonModel`.

Граф суммирует коэффициенты int32 и оператором `Scan` последовательно выбирает метку с учётом предыдущего предсказания. При равных оценках выбирается первая метка. Выход `labels` имеет тип int64 и размер `[tokens]`. Формат — ONNX IR 9, opset 17, веса встроены в файл.

Токенизация и перевод меток в UTF-16-интервалы выполняются в .NET. Правила email, телефона, реквизитов, исключения полей, контекст и подстановки выполняются конвейером ag-privacy. Граф содержит перцептрон распознавания ФИО. Компактный классификатор формы фамилии и теневые наблюдатели остаются отдельными частями конвейера.

Экспорт не требует исходного словаря фамилий. Во время инференса используются веса. Модель `.onnx` загружается из локального доверенного артефакта, размер которого ограничен 1 МиБ. Лимиты токенизации совпадают с `MicroPersonModel`. Ошибки инференса переводятся в исключение, которое обычные точки входа маскирования обрабатывают как сбой.

## Проверка эквивалентности

```sh
dotnet test tests/AgPrivacy.Onnx.Tests -c Release
.onnx-venv/bin/python -m unittest discover -s tools/onnx -p 'test_*.py'
```

Тесты сравнивают каждую из двух моделей на 200 синтетических строках с кириллицей, транслитерацией, логинами и служебным текстом. Отдельно проверяются обратная связь предыдущей метки, равные оценки, пустой вход, 8192 токена, параллельные вызовы, освобождение и сбой backend. В потоковых проверках сравниваются все выходные байты для 80 записей с разным экранированием.

Проверка эквивалентности показывает сохранение поведения экспортированной модели на этих входах. Качество распознавания и ложные маски определяются обученными весами и правилами. Производительность ONNX нужно измерять для конкретного размера сообщения и конфигурации приложения.

API и операторы описаны в официальной документации [ONNX Runtime C#](https://onnxruntime.ai/docs/tutorials/csharp/basic_csharp.html) и [ONNX Scan](https://onnx.ai/onnx/operators/onnx__Scan.html).
