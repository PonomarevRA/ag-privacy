# AgPrivacy.Core

Локальная библиотека .NET 10 для маскирования JSON, сообщений логов, CSV и XML. Поддерживает HMAC-псевдонимы, подстановку букв и цифр с сохранением разделителей, локальные модели ФИО и потоковую обработку.

Для установки из исходников соберите пакет командой `dotnet pack src/AgPrivacy.Core -c Release -o ./packages`. Добавьте каталог `packages` как локальный источник NuGet и установите `AgPrivacy.Core` версии `0.2.0`.

Для обработки логов используйте `StreamingPrivacyMasker`. Для локального сравнения JSON используйте `SanitizeJsonForDisplay`, `SoftPartMasker.SanitizeJson` и `SanitizeTypedLogForDisplay`. Поля `Allowed` и `SafeForAgent` отражают статус конкретной операции. Строгую границу выдачи обеспечивает `PrivacyEngine.SanitizeJson`. Подробный контракт включён в пакет.

Примеры и инструкции находятся в [публичном репозитории](https://github.com/PonomarevRA/ag-privacy). Лицензии сторонних данных и моделей перечислены в `notices/THIRD-PARTY-NOTICES.TXT`.
