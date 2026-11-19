using System.Text.Json;

namespace AgPrivacy;

/// <summary>Recognize supported values in fields that have no named display rule.</summary>
internal static class DisplayValueFormats
{
    /// <summary>Ordinary numeric and Boolean values can retain their JSON types in the playground.</summary>
    internal static bool IsOrdinaryPrimitive(JsonValueKind kind) =>
        kind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False;

    /// <summary>Require a whole value match so fragments inside free text do not select a partial mask.</summary>
    internal static string? RuleFor(string value)
    {
        if (RegexDetector.HasMatch(value, "EMAIL", wholeValue: true)) return "EMAIL";
        if (SoftPartFormats.IsPhoneValue(value)) return "PHONE";
        return SoftPartFormats.IsAgreementValue(value) ? "AGREEMENT" : null;
    }

    /// <summary>Select a full mask when a free string contains a detected sensitive span.</summary>
    internal static string? RuleForText(string value, PrivacyPolicy policy, IPersonDetector? persons)
    {
        string? format = RuleFor(value);
        if (format is not null) return format;

        var spans = TextRedactor.FindSpans(value, policy, persons);
        if (spans.Count == 1 && spans[0].Start == 0 && spans[0].Length == value.Length)
            return spans[0].Type;

        if (spans.Count > 0 || JsonFieldNames.ContainsPhone(value) || SoftPartFormats.ContainsAgreement(value) ||
            CredentialsRedactor.ContainsAuthorizationToken(value))
            return "TEXT";

        return null;
    }

    /// <summary>Apply the same format mask used for an explicitly named field.</summary>
    internal static string Mask(string value, string? rule) => rule switch
    {
        "EMAIL" => SoftPartFormats.Email(value),
        "PHONE" => SoftPartFormats.Phone(value),
        "AGREEMENT" => SoftPartFormats.Agreement(value),
        null => value,
        _ => SoftPartFormats.FullMask
    };
}
