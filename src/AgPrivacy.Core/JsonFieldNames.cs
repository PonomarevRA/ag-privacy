using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Field names in the playground are preserved except for recognizable contact details.</summary>
internal static partial class JsonFieldNames
{
    /// <summary>Detect an email address or a phone number in the text of the key itself.</summary>
    internal static string? ContactRule(string name)
    {
        if (RegexDetector.HasMatch(name, "EMAIL")) return "KEY_EMAIL";
        return ContainsPhone(name) ? "KEY_PHONE" : null;
    }

    /// <summary>Detect an explicitly formatted phone within a key or string.</summary>
    internal static bool ContainsPhone(string value) => PhoneNumber().IsMatch(value);

    /// <summary>Recognize a standalone phone with the same evidence required for a sensitive key.</summary>
    internal static bool MatchesWholePhone(string value)
    {
        var match = PhoneNumber().Match(value);
        return match.Success && match.Length == value.Length;
    }

    // Require an international prefix or a separated Russian trunk prefix and area code.
    /// <summary>Expose the compiled matches to selective log masking.</summary>
    internal static MatchCollection PhoneMatches(string text) => PhoneNumber().Matches(text);

    [GeneratedRegex(@"(?:\+[0-9](?:[ .()\-]*[0-9]){6,14}|(?<![\p{L}\p{N}])[78](?:[ .-]*\([0-9]{3}\)|[ .-]+[0-9]{3})[ .-]*[0-9]{3}[ .-]*[0-9]{2}[ .-]*[0-9]{2})(?![\p{L}\p{N}]|[ .()\-]*[0-9])",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex PhoneNumber();
}
