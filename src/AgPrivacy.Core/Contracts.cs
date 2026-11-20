namespace AgPrivacy;

/// <summary>Распознанный интервал в UTF-16; исходное значение в метаданные результата не включается.</summary>
public readonly record struct EntitySpan(int Start, int Length, string Type, int Priority = 0, bool UrlEncoded = false)
{
    internal int JsonEscapeLayers { get; init; }
    internal bool JsonNumber { get; init; }
}

/// <summary>
/// Opt-in offline routing for two existing detectors. Text reads narrative outside complete JSON,
/// Structured reads decoded message values and known query parameters, and Mixed runs both.
/// </summary>
public enum LogAnalysisMode
{
    Text,
    Structured,
    Mixed
}

/// <summary>Необязательный локальный распознаватель. Его прогноз не является разрешением выдавать текст.</summary>
public interface IPersonDetector
{
    string Version { get; }
    IReadOnlyList<EntitySpan> Find(string text);
}

/// <summary>The start and length of a replacement in the displayed text, measured in UTF-16.</summary>
public readonly record struct MaskHighlight(int Start, int Length);

/// <summary>Formatted masked output and the locations of actual replacements.</summary>
public sealed record MaskPreview(string Text, IReadOnlyList<MaskHighlight> Highlights);

/// <summary>Только очищенный результат. Strict и heuristic имеют различную гарантию выдачи.</summary>
public sealed record PrivacyResult(bool Allowed, bool SafeForAgent, string Status,
    string? Text, System.Text.Json.Nodes.JsonNode? Data, int Replacements,
    string PolicyVersion, string ModelVersion, string[] DisclosedFields, string? DisclosureReceiptId)
{
    /// <summary>Counts of replacements by applied rule for local display results.</summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyDictionary<string, int>? ReplacementsByType { get; init; }

    /// <summary>Optional rendering information for the local comparison UI.</summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public MaskPreview? Preview { get; init; }

    public string ProtectionMode => Status switch { "disabled-by-human-installation-choice" => "off", "credentials-only-human-installation-choice" => "credentials-only", "privacy-processing-blocked" => "blocked", "heuristic-not-security-qualified" => "heuristic", "soft-part-redaction" => "soft-part", "guid-only-redaction-for-display" => "guid-only", "typed-log-redaction-for-display" => "log-types", _ => "strict" };
    public bool AuthorizedByHumanChoice => Status is "disabled-by-human-installation-choice" or "credentials-only-human-installation-choice";
    public bool OriginalReplaced => Replacements > 0;
    /// <summary>Host displays this verbatim and requires the agent to mention masking; never includes samples or entity categories.</summary>
    public string? AgentNotice => Status switch
    {
        "disabled-by-human-installation-choice" => "ag-privacy выключен пользователем при установке. Данные передаются в оригинале.",
        "credentials-only-human-installation-choice" => OriginalReplaced ? "Часть данных скрыта ag-privacy. Минимальный режим выбран пользователем; остальные данные могут передаваться в оригинале." : "ag-privacy работает в минимальном режиме по выбору пользователя; остальные данные могут передаваться в оригинале.",
        "strict-redaction-for-display" => "Правила маскируют чувствительные поля и распознанные значения. Остальные данные могут сохраниться в исходном виде.",
        "typed-log-redaction-for-display" => "Режим маскирует распознанные фрагменты. Значения MasterId и остальной текст могут сохраниться в исходном виде.",
        "guid-only-redaction-for-display" => "Режим маскирует GUID. Значения MasterId и остальное содержимое сохраняются.",
        "soft-part-redaction" => "Результат soft-part может содержать части исходных данных и значения полей без маскировки.",
        _ => OriginalReplaced ? "Часть данных скрыта ag-privacy. Исходные значения агенту недоступны." : null
    };
    public bool MustDiscloseMasking => OriginalReplaced;
}

/// <summary>Фиксированные ограничения на одну неделимую операцию до сериализации ответа.</summary>
public static class PrivacyLimits
{
    public const int InputBytes = 262144;
    public const int Nodes = 10000;
    public const int Depth = 32;
    public const int Entities = 4096;
}
