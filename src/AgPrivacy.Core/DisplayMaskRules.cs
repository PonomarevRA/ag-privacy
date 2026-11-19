using System.Collections.Frozen;

namespace AgPrivacy;

/// <summary>Stable codes and descriptions for the rule labels exposed in local display markers.</summary>
public static class DisplayMaskRules
{
    public static IReadOnlyDictionary<string, string> Descriptions { get; } =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["TEXT"] = "Полная маска текстового поля или строки с чувствительным фрагментом",
            ["NUMBER"] = "Числовое значение JSON",
            ["BOOLEAN"] = "Логическое значение JSON",
            ["KEY_EMAIL"] = "Адрес электронной почты в ключе JSON",
            ["KEY_PHONE"] = "Номер телефона в ключе JSON",
            ["KEY"] = "Ключ JSON",
            ["PERSON"] = "Имя, фамилия или ФИО",
            ["DATE"] = "Поле даты, например дата рождения или договора",
            ["AGREEMENT"] = "Номер договора по имени поля или формату значения. В soft-part числовой формат заменяется на 00-000000/00",
            ["EMAIL"] = "Адрес электронной почты по имени поля или формату значения",
            ["PHONE"] = "Номер телефона по имени поля или формату значения",
            ["ADDRESS"] = "Поле адреса",
            ["KLOGIN"] = "Логин клиента",
            ["TRDACC"] = "Номер брокерского счёта",
            ["ACCOUNT"] = "Номер счёта или карты",
            ["INN"] = "ИНН",
            ["TIN"] = "Иностранный налоговый идентификатор",
            ["KPP"] = "КПП",
            ["OGRN"] = "ОГРН",
            ["BIK"] = "БИК",
            ["IP"] = "Сетевой адрес IPv4 или IPv6",
            ["SECRET"] = "Пароль, токен или другой секрет",
            ["GUID"] = "Идентификатор UUID",
            ["TRACE_ID"] = "Стабильный псевдоним идентификатора трассировки",
            ["IDENTIFIER"] = "Идентификатор из схемы поля",
            ["URL"] = "Веб-адрес",
            ["PATH"] = "Путь к файлу или каталогу"
        }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>Refine display labels from field names while keeping the existing HMAC domain.</summary>
    internal static string ForField(string? field, string type) => field switch
    {
        null => type,
        _ => PrivacyPolicy.NormalizeField(field) switch
        {
            "codeword" or "otp" or "cvv" => "SECRET",
            "fullnameeng" or "fullnamerus" => "PERSON",
            "birthdate" or "dateofbirth" or "датарождения" or "issuedate" or "documentissuedate" or
                "датавыдачидокумента" or "agreementdate" or "датазаключениядоговора" or "date" or "дата" => "DATE",
            "agreementnumber" or "contractnumber" or "номердоговора" or "nonstandardagreementnumber" or
                "forwardcontractnumber" or "structuredproductagreementnumber" => "AGREEMENT",
            "bankaccount" or "accountnumber" or "clientaccount" or "cardnumber" or "номеркарты" => "ACCOUNT",
            "brokeraccount" or "brokeraccountnumber" or "номерброкерскогосчёта" => "TRDACC",
            "workphone" or "homephone" or "mobilephone" or "телефон" or "fax" or "факс" => "PHONE",
            "tin" => "TIN",
            _ => type
        }
    };
}
