# ag-privacy

[Русский](README.ru.md) · [English](README.en.md) · [Экспериментальная модель ФИ и ФИО](docs/recall337-preview.ru.md) · [Модель ФИ и ФИО v1.0.0](docs/fi-fio-model-v1.ru.md)

Локальная библиотека .NET 10 для маскирования чувствительных данных перед просмотром логов, обработкой файлов и передачей результата в другие системы. Обрабатывает JSON, сообщения внутри JSON, CSV, TSV и XML. Работает через .NET API, потоковый CLI и локальный UI.

ФИО и логины определяются правилами, компактными локальными моделями и ближайшим контекстом. Фамильный классификатор хранит веса для групп символов. Словарь фамилий используется как внешний вход обучения. Состав моделей и алгоритм описаны в [схеме обработки](docs/how-it-works.md).

## Установка из исходников

Нужен .NET SDK 10.0.102 или более новый SDK из ветки 10.0.1xx.

```sh
git clone https://github.com/PonomarevRA/ag-privacy.git
cd ag-privacy
dotnet build src/AgPrivacy.Core -c Release
dotnet build src/AgPrivacy.Cli -c Release
```

Собрать локальный пакет NuGet и подключить его в свой проект можно так. Команды выполняются из корня клонированного репозитория.

```sh
dotnet pack src/AgPrivacy.Core -c Release -o ./packages
dotnet new console --framework net10.0 -o ./demo-app
dotnet add ./demo-app package AgPrivacy.Core --version 0.2.0 --source ./packages
```

Для разработки в общей директории подойдёт ссылка на проект.

```sh
dotnet add /path/to/your-app reference /path/to/ag-privacy/src/AgPrivacy.Core/AgPrivacy.Core.csproj
```

## Попробовать в браузере

```sh
dotnet run --project tools/AgPrivacy.Playground -c Release
```

Откройте [http://127.0.0.1:47832](http://127.0.0.1:47832). Введите JSON и нажмите «Сравнить режимы». UI показывает strict, soft-part и «Типы данных в логах» рядом, подсвечивает замены и выводит сводку по правилам. В UI метка strict обозначает режим просмотра JSON.

CSV, TSV и XML можно загрузить файлом и скачать с суффиксом `_masked`. Для таблиц UI определяет разделитель и кодировку UTF-8 или Windows-1251. Перед скачиванием разделитель можно поменять. Сервер слушает только loopback. Ключ подстановок создаётся заново при каждом запуске UI.

## Сгенерированные примеры до и после

```sh
dotnet run --project examples/Quickstart -c Release -- ./demo-output
```

Команда создаёт десять файлов с вымышленными значениями, включая результаты маскирования JSON, логов, CSV и XML. Выходные JSON разбираются, проверяются сохранение `trace.id` и удаление тестовых email и токена. Подстановки зависят от случайного ключа конкретного запуска. В репозитории есть [пример одного запуска](examples/generated/README.md).

| Вход | Результат |
| --- | --- |
| `email`, `tags`, `status` как обычные имена ключей | Имена сохраняются в режимах просмотра |
| Email или телефон внутри имени ключа | Чувствительная часть ключа маскируется |
| `status: approved`, `category: demo`, `numberId: 42` | Обычные значения сохраняются в режимах просмотра |
| Email или телефон в поле с произвольным именем | Определяется правило по значению |
| ФИО, email или токен внутри `message` | Маскируется найденный фрагмент |
| Одинаковый `trace.id` у нескольких записей в `stream-log` | Значение сохраняется для связи событий |
| CSV `fullName` или XML `<fullName>` | Тип определяется по заголовку или тегу |
| `isin`, `ticker` | Исключения по умолчанию, список настраивается |

## Использование из C#

```csharp
using System.Security.Cryptography;
using AgPrivacy;

var policy = PrivacyPolicy.Compile(
    """{"schemaVersion":"ag-privacy-policy-v1","displayFieldExceptions":["isin","ticker"]}"""u8);
byte[] key = RandomNumberGenerator.GetBytes(32);
using var aliases = new Pseudonymizer(key, "my-application");
CryptographicOperations.ZeroMemory(key);

var engine = new PrivacyEngine(policy, aliases);
var result = engine.SanitizeJsonForDisplay(
    """{"email":"sample.person@example.test","status":"approved"}""");
if (!result.Allowed)
    throw new InvalidOperationException("Masking failed");

Console.WriteLine(result.Data!.ToJsonString());
```

Приложение управляет ключом и областью `scope`. Для повторяемых подстановок между запусками передавайте один защищённый ключ и одну область. Ключ должен содержать от 32 до 128 случайных байт.

Для потоковой обработки передайте открытые `Stream` в `StreamingPrivacyMasker.MaskAsync`, `StructuredPrivacyMasker.MaskCsvAsync` или `MaskXmlAsync`. Полный пример с загрузкой моделей находится в [examples/Quickstart](examples/Quickstart/Program.cs).

## Потоковый CLI

Создайте локальный ключ в закрытом файле. Для Linux и macOS доступны команды ниже с Python 3. Файл создаётся один раз и остаётся на вашей машине.

```sh
python3 -c 'import os,secrets; f=os.open(".demo.key",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,secrets.token_bytes(32)); os.close(f)'
dotnet run --project src/AgPrivacy.Cli -c Release -- stream-log \
  policies/default.json .demo.key demo-scope demo-journal.ndjson \
  models/person-default.bin --person-prose-model models/person-prose.bin \
  < examples/generated/logs_before.ndjson > demo-masked.ndjson
```

stdout содержит замаскированный поток. Отдельный журнал содержит правило, подстановку и непрозрачный идентификатор записи. Путь журнала должен быть новым при каждом запуске. Общий размер входного потока не ограничен целиком. Окна и отдельные структурные элементы ограничены для контроля памяти.

```sh
dotnet run --project src/AgPrivacy.Cli -c Release -- stream-csv \
  policies/default.json .demo.key demo-scope csv-journal.ndjson semicolon \
  < examples/generated/table_before.csv > demo-masked.csv

dotnet run --project src/AgPrivacy.Cli -c Release -- stream-xml \
  policies/default.json .demo.key demo-scope xml-journal.ndjson \
  < examples/generated/document_before.xml > demo-masked.xml
```

CLI принимает UTF-8. Для CSV разделитель задаётся как `comma`, `semicolon` или `tab`. Работа с Windows-1251 и автоматическим определением разделителя реализована в UI.

## Режимы и ограничения

`PrivacyEngine.SanitizeJson` предоставляет строгую границу выдачи с заменой неизвестных значений. `SanitizeJsonForDisplay`, `SoftPartMasker` и типизированная подстановка предназначены для просмотра и сохраняют распознанную обычную информацию. Проверяйте поля `Allowed`, `SafeForAgent` и статус результата перед дальнейшей передачей. Описание — в [контракте](docs/contract.md).

Модели могут пропускать чувствительные данные и давать ложные срабатывания. Форматная подстановка сохраняет длины и разделители, а одинаковые значения могут сопоставляться в пределах одного ключа и области. Настройки исключений полей требуют проверки на ваших данных.

## Проверка, обучение и наблюдаемость

```sh
dotnet test tests/AgPrivacy.Tests -c Release
node --test tests/javascript/privacy-host.test.mjs
```

Исходники тренера ФИО находятся в `tools/AgPrivacy.Train`, тренера формы фамилии — в `tools/surname-model/train.py`. Входные файлы обучения передаются внешними путями. Форматы и принцип разделения обучения и проверки описаны в [документации моделей](docs/models.md).

UI экспортирует Prometheus-метрики по [http://127.0.0.1:47832/metrics](http://127.0.0.1:47832/metrics). Для собственного хоста библиотека предоставляет `System.Diagnostics.Metrics.Meter` с именем `AgPrivacy`. Значения исходных данных в метки метрик не попадают.

Код распространяется по [MIT](LICENSE). Условия сторонних компонентов, словаря имён и источников обучения приведены в [уведомлениях](notices/THIRD-PARTY-NOTICES.TXT).

## ONNX Runtime

Модели ФИО и логинов доступны в ONNX. В [docs/onnx.md](docs/onnx.md) находятся экспорт собственных весов, подключение в .NET и команда запуска готового потокового примера.

## WebNN

Модели ФИО работают в браузере через WebNN или JavaScript. Пример показывает фактический backend и причину fallback. [Русская инструкция](docs/webnn.md) · [English guide](docs/webnn.en.md).
