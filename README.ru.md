# ag-privacy

[Русский](README.ru.md) · [English](README.en.md) · [Экспериментальная модель ФИ и ФИО](docs/recall337-preview.ru.md) · [Модель ФИ и ФИО v1.0.0](docs/fi-fio-model-v1.ru.md) · [ФИО в нижнем регистре · preview](docs/fio-lowercase-preview.ru.md) · [Основная модель ФИ и ФИО v2.0.0](docs/fi-fio-model-v2.ru.md)

Локальная библиотека .NET 10 для маскирования JSON, сообщений логов, CSV, TSV и XML. Доступны потоковый CLI, локальный UI, ONNX Runtime и браузерный детектор ФИО через WebNN. Словари фамилий используются как внешние данные обучения. При обработке работают веса моделей, правила формата и контекст.

## Установка

Нужен .NET SDK 10.0.102 или совместимый SDK 10.0.1xx.

```sh
git clone https://github.com/PonomarevRA/ag-privacy.git
cd ag-privacy
dotnet build src/AgPrivacy.Core -c Release
dotnet build src/AgPrivacy.Cli -c Release
```

Для установки локального NuGet-пакета выполните команды из корня репозитория.

```sh
dotnet pack src/AgPrivacy.Core -c Release -o ./packages
dotnet new console --framework net10.0 -o ./demo-app
dotnet add ./demo-app package AgPrivacy.Core --version 0.2.0 --source ./packages
```

## Локальный UI

```sh
dotnet run --project tools/AgPrivacy.Playground -c Release
```

Откройте [127.0.0.1:47832](http://127.0.0.1:47832). Кнопка «Сравнить режимы» показывает strict, soft-part и типизированную подстановку рядом, с подсветкой замен и сводкой правил. В UI strict обозначает режим просмотра JSON.

Для CSV, TSV и XML доступны загрузка и скачивание результата. UI определяет UTF-8 или Windows-1251 и разделитель таблицы. Выбранный разделитель сохраняется при скачивании, к имени файла добавляется `_masked`.

[Синтетические примеры до и после](https://github.com/PonomarevRA/ag-privacy/tree/main/examples/generated) содержат результаты реального запуска и отмеченные ограничения детектора.

## Подключение в C#

```sh
dotnet add /path/to/your-app reference /path/to/ag-privacy/src/AgPrivacy.Core/AgPrivacy.Core.csproj
```

```csharp
using System.Security.Cryptography;
using AgPrivacy;

var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
byte[] key = RandomNumberGenerator.GetBytes(32);
using var aliases = new Pseudonymizer(key, "my-application");
CryptographicOperations.ZeroMemory(key);
var engine = new PrivacyEngine(policy, aliases);

var result = engine.SanitizeJsonForDisplay(
    """{"email":"sample.person@example.test","status":"approved"}""");
if (!result.Allowed) throw new InvalidOperationException("Masking failed");
Console.WriteLine(result.Data!.ToJsonString());
```

Приложение управляет секретным ключом и областью подстановок. Одинаковые ключ, область, тип и значение дают устойчивую подстановку. Для воспроизводимости между запусками храните ключ в защищённом хранилище приложения.

## Потоковый CLI

На Linux и macOS следующий пример использует Python 3 для создания закрытого файла ключа. Файлы ключа и журнала создаются один раз.

```sh
python3 -c 'import os,secrets; f=os.open(".demo.key",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,secrets.token_bytes(32)); os.close(f)'
dotnet run --project src/AgPrivacy.Cli -c Release -- stream-log \
  policies/default.json .demo.key demo-scope demo-journal.ndjson \
  < examples/Onnx/input.ndjson > masked.ndjson
```

stdout содержит замаскированный UTF-8 поток. Отдельный журнал содержит типы правил, подстановки и непрозрачные идентификаторы. В `stream-log` сохраняется `trace.id` для связи событий. Для CSV используйте `stream-csv` с разделителем `comma`, `semicolon` или `tab`, для XML — `stream-xml`.

## ONNX Runtime

```sh
dotnet run --project examples/Onnx -c Release -- \
  models/person-default.onnx models/person-prose.onnx \
  < examples/Onnx/input.ndjson > onnx-masked.ndjson
```

[Инструкция ONNX](docs/onnx.md) описывает подключение `AgPrivacy.Onnx`, сборку пакета, экспорт своих весов и ограничения графа.

## WebNN в браузере

Из корня репозитория запустите статический сервер на loopback.

```sh
python3 -m http.server 47833 --bind 127.0.0.1
```

Откройте [браузерный пример](http://127.0.0.1:47833/examples/WebNN/index.html). Он показывает фактический backend. В режиме `auto` при недоступности WebNN используется JavaScript с указанием причины. Режим «Только WebNN» возвращает ошибку при недоступном API или сбое устройства.

[Инструкция WebNN](docs/webnn.md) содержит JavaScript API, условия доступности и результаты проверки. Для WebNN используются исходные `person-default.bin` и `person-prose.bin`. Браузерный адаптер возвращает интервалы ФИО. Правила других типов данных и подстановки выполняет основной конвейер.

## Проверка и ограничения

Для тестов JavaScript нужен Node.js 20 или новее.

```sh
dotnet test tests/AgPrivacy.Tests -c Release
dotnet test tests/AgPrivacy.Onnx.Tests -c Release
node --test tests/javascript/*.test.mjs
```

`PrivacyEngine.SanitizeJson` предоставляет строгую границу выдачи. Режимы просмотра и браузерный детектор допускают пропуски и ложные маски. Перед передачей результата проверяйте `Allowed`, `SafeForAgent` и контракт выбранного API.

Источники открытых данных и лицензии приведены в [уведомлениях](notices/THIRD-PARTY-NOTICES.TXT). Текст и модели обрабатываются локально. Браузерному примеру нужны статические файлы с того же сервера.

## Маскирование ФИО в JSON-логах

Для значения JSON-полей `fio`, `ФИО` и `fullName` работает правило PERSON по схеме поля. Поля `firstName`, `lastName` / `surname` и `middleName` / `patronymic` обрабатываются по той же схеме. Поддерживаются обычный JSON, Unicode-экранирование и JSON внутри строки `message`. Ключи и служебные значения `trace.id`, `ticker` и `status` сохраняются в проверенных сценариях.

Для свободного текста используйте `SanitizeTypedLogForDisplay` с режимом `LogAnalysisMode.Mixed`. В этом режиме отдельно передаются распознаватели свободного текста и декодированных значений JSON. Явные поля PERSON обрабатываются и при отсутствии модели.
