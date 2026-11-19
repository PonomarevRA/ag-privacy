using System.Globalization;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Pure display transformations. An invalid or ambiguous format falls back to four stars.</summary>
internal static partial class SoftPartFormats
{
    internal const string FullMask = "****";
    private const string Letters = @"[\p{L}\p{M}'’-]+";
    private const string NumericAgreementShape = @"[0-9]+-[0-9]+/[0-9]+";
    private const string StandardAgreementShape = @"([\p{L}]{1,8}-?)([0-9][0-9 -]*)([0-9]{2})(/[0-9]{2}-[\p{L}]{1,8})";

    /// <summary>Keep an exempt value verbatim.</summary>
    internal static string Keep(string value) => value;

    /// <summary>Apply a constant mask irrespective of input length.</summary>
    internal static string Full(string _) => FullMask;

    /// <summary>Keep the first text element of a surname or address field.</summary>
    internal static string Initial(string value) =>
        value.Length > 0 && value.Length == StringInfo.GetNextTextElementLength(value) ? value : KeepEdges(value, 1, 0);

    /// <summary>Keep the first and last text elements under the generic partial rule.</summary>
    internal static string Partial(string value) => KeepEdges(value, 1, 1);

    /// <summary>Keep the final two text elements of a broker account.</summary>
    internal static string BrokerAccount(string value) => KeepEdges(value, 0, 2);

    /// <summary>Keep the final four text elements of a client account or card.</summary>
    internal static string ClientAccount(string value) => KeepEdges(value, 0, 4);

    /// <summary>Keep the first four and final three text elements of a known nonstandard contract number.</summary>
    internal static string NonstandardAgreement(string value) => KeepEdges(value, 4, 3);

    /// <summary>Keep given name and patronymic after a surname, including a surname with spaces.</summary>
    internal static string FullName(string value)
    {
        var match = NamePattern().Match(value);
        if (!match.Success) return FullMask;

        string surname = match.Groups[1].Value;
        return Initial(surname) + value[surname.Length..];
    }

    /// <summary>Replace only the year of a valid date in one of the three documented formats.</summary>
    internal static string Date(string value)
    {
        foreach (var (format, yearOffset) in DateFormats)
        {
            if (DateTime.TryParseExact(value, format, CultureInfo.InvariantCulture, DateTimeStyles.None, out _))
                return value[..yearOffset] + FullMask + value[(yearOffset + 4)..];
        }
        return FullMask;
    }

    private static readonly (string Format, int Offset)[] DateFormats =
        [("dd-MM-yyyy", 6), ("yyyy-MM-dd", 0), ("dd'/'MM'/'yyyy HH:mm:ss", 6)];

    /// <summary>Preserve the first and last digits and replace surrounding characters.</summary>
    internal static string Registration(string value)
    {
        int first = value.AsSpan().IndexOfAnyInRange('0', '9');
        int last = value.AsSpan().LastIndexOfAnyInRange('0', '9');
        if (first < 0 || first == last || value.Length <= 2) return FullMask;

        int[] starts = StringInfo.ParseCombiningCharacters(value);
        int firstElement = Array.BinarySearch(starts, first);
        int lastElement = Array.BinarySearch(starts, last);
        if (firstElement < 0 || lastElement < 0 || starts.Length <= 2) return FullMask;

        var masked = new string('*', starts.Length).ToCharArray();
        masked[firstElement] = value[first];
        masked[lastElement] = value[last];
        return new string(masked);
    }

    /// <summary>Recognize only an explicit international or formatted local phone that can be masked.</summary>
    internal static bool IsPhoneValue(string value) => PhonePattern().IsMatch(value) && JsonFieldNames.MatchesWholePhone(value);

    /// <summary>Recognize distinctive contract structures without treating opaque alphanumeric codes as contracts.</summary>
    internal static bool IsAgreementValue(string value) =>
        NumericAgreementPattern().IsMatch(value) || AgreementPattern().IsMatch(value);

    /// <summary>Detect a supported contract number inside a longer string.</summary>
    internal static bool ContainsAgreement(string value) => EmbeddedAgreementPattern().IsMatch(value);

    /// <summary>Mask the four digits immediately preceding the final three, preserving phone separators.</summary>
    internal static string Phone(string value) => Phone(value, preserve: false);

    /// <summary>Keep a well-formed phone explicitly linked to an FS.</summary>
    internal static string LinkedPhone(string value) => Phone(value, preserve: true);

    /// <summary>Validate the same phone format before either masking or preserving it.</summary>
    private static string Phone(string value, bool preserve)
    {
        if (!PhonePattern().IsMatch(value)) return FullMask;

        char[]? output = preserve ? null : value.ToCharArray();
        int seen = 0;
        for (int i = value.Length - 1; i >= 0; i--)
        {
            if (!char.IsAsciiDigit(value[i])) continue;
            seen++;
            if (output is not null && seen is >= 4 and <= 7) output[i] = '*';
        }

        if (seen < 7) return FullMask;
        return output is null ? value : new string(output);
    }

    /// <summary>Mask the mailbox according to its length and end at the @ shown in the rule examples.</summary>
    internal static string Email(string value)
    {
        var match = EmailPattern().Match(value);
        if (!match.Success) return FullMask;

        string mailbox = match.Groups[1].Value;
        int count = new StringInfo(mailbox).LengthInTextElements;
        int visible = count > 4 ? 3 : count > 1 ? 1 : 0;
        return KeepEdges(mailbox, visible, 0) + "@";
    }

    /// <summary>Preserve the recognized login prefix and final two digits.</summary>
    internal static string Login(string value)
    {
        var match = LoginPattern().Match(value);
        return match.Success ? MaskAffixedNumber(match) : FullMask;
    }

    /// <summary>Use a fixed template for numeric contracts and the established masks for other known shapes.</summary>
    internal static string Agreement(string value)
    {
        if (NumericAgreementPattern().IsMatch(value)) return "00-000000/00";

        var match = AgreementPattern().Match(value);
        if (match.Success) return MaskAffixedNumber(match) + match.Groups[4].Value;
        return NonstandardPattern().IsMatch(value) ? NonstandardAgreement(value) : FullMask;
    }

    /// <summary>Replace the serial body of a recognized login or contract while retaining its suffix.</summary>
    private static string MaskAffixedNumber(Match match) =>
        match.Groups[1].Value + new string('*', match.Groups[2].Length) + match.Groups[3].Value;

    /// <summary>Mask a middle span by text element, with a full mask when no hidden span would remain.</summary>
    private static string KeepEdges(string value, int prefix, int suffix)
    {
        int[] starts = StringInfo.ParseCombiningCharacters(value);
        if (starts.Length <= prefix + suffix) return FullMask;

        int suffixStart = suffix == 0 ? value.Length : starts[^suffix];
        return value[..starts[prefix]] + new string('*', starts.Length - prefix - suffix) + value[suffixStart..];
    }

    /// <summary>Expose the compiled matches to selective log masking.</summary>
    internal static MatchCollection AgreementMatches(string text) => EmbeddedAgreementPattern().Matches(text);

    [GeneratedRegex(@"\A(" + Letters + @"(?: +" + Letters + @")*) +" + Letters + @" +" + Letters + @"\z", RegexOptions.NonBacktracking)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"\A\+?[0-9 ()-]+\z", RegexOptions.NonBacktracking)]
    private static partial Regex PhonePattern();

    [GeneratedRegex(@"\A([^@\s]+)@[^@\s]+\z", RegexOptions.NonBacktracking)]
    private static partial Regex EmailPattern();

    [GeneratedRegex(@"\A([\p{L}]{1,8}-)([0-9]+)([0-9]{2})\z", RegexOptions.NonBacktracking)]
    private static partial Regex LoginPattern();

    [GeneratedRegex(@"\A" + NumericAgreementShape + @"\z", RegexOptions.NonBacktracking)]
    private static partial Regex NumericAgreementPattern();

    [GeneratedRegex(@"\A" + StandardAgreementShape + @"\z", RegexOptions.NonBacktracking)]
    private static partial Regex AgreementPattern();

    [GeneratedRegex(@"(?<![\p{L}\p{N}])(?:" + NumericAgreementShape + "|" + StandardAgreementShape + @")(?![\p{L}\p{N}])",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex EmbeddedAgreementPattern();

    [GeneratedRegex(@"\A(?:[\p{L}]{4}[0-9]+[\p{L}]{3}|[0-9]/[0-9]{2}[0-9 /-]+[0-9]/[\p{L}])\z", RegexOptions.NonBacktracking)]
    private static partial Regex NonstandardPattern();
}
