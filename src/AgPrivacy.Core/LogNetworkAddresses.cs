using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Recognize complete network addresses in API logs and validate their syntax.</summary>
internal static partial class LogNetworkAddresses
{
    /// <summary>Collect address intervals, excluding explicitly labelled four-part software versions.</summary>
    internal static void Add(string text, List<EntitySpan> spans)
    {
        if (text.AsSpan().IndexOfAny('.', ':') < 0) return;
        foreach (var match in Candidates().EnumerateMatches(text))
        {
            var value = text.AsSpan(match.Index, match.Length);
            if (value.Contains(':'))
            {
                if (!IPAddress.TryParse(value, out var address) ||
                    address.AddressFamily != AddressFamily.InterNetworkV6) continue;
            }
            else if (!IsDottedDecimal(value) || IsVersion(text, match.Index)) continue;
            spans.Add(new(match.Index, match.Length, "IP", 160));
        }
    }

    /// <summary>Require four decimal octets with no shorthand, padding or overflow.</summary>
    private static bool IsDottedDecimal(ReadOnlySpan<char> value)
    {
        int octets = 0;
        foreach (var range in value.Split('.'))
        {
            var part = value[range];
            if (part.Length is < 1 or > 3 || part.Length > 1 && part[0] == '0') return false;
            int number = 0;
            foreach (char digit in part)
            {
                if (!char.IsAsciiDigit(digit)) return false;
                number = number * 10 + digit - '0';
            }
            if (number > 255) return false;
            octets++;
        }
        return octets == 4;
    }

    /// <summary>Look only at the label adjoining the value.</summary>
    private static bool IsVersion(string text, int start)
    {
        int size = Math.Min(start, 48);
        return VersionLabel().IsMatch(text.AsSpan(start - size, size));
    }

    [GeneratedRegex(@"(?<![\w.:])(?:[a-fA-F0-9]*:[a-fA-F0-9:]*:[a-fA-F0-9:]*[a-fA-F0-9:](?:\.[0-9]{1,3}){0,3}(?![\w:]|\.[\w])|::(?![\w:]|\.[\w]))|(?<![\w.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![\w]|\.[\w]|:(?![0-9]))",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex Candidates();

    [GeneratedRegex(@"\b(?:version|build(?:[._-]?version)?|release|версия)[""\x27]?\s*[:=]\s*[""']?\s*\z",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 100)]
    private static partial Regex VersionLabel();
}
