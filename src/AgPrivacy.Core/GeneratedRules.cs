using System.Text.RegularExpressions;
namespace AgPrivacy;
/// <summary>Generated at build time from trusted rules/regex.json. Do not edit by hand.</summary>
public static partial class GeneratedRules
{
    public const string Version = "3d1dfc7458cdf920e81879e15fabeab7dcb1bfe52aae061583b6e2da16077434";
    public static readonly RegexRule[] All = [
        new("guid", "GUID", Pattern0()),
        new("guid-compact", "GUID", Pattern1()),
        new("klogin", "KLOGIN", Pattern2()),
        new("email", "EMAIL", Pattern3()),
        new("jwt", "SECRET", Pattern4()),
        new("api-token", "SECRET", Pattern5()),
        new("private-key", "SECRET", Pattern6()),
        new("inn-labeled", "INN", Pattern7()),
        new("kpp-labeled", "KPP", Pattern8()),
        new("trdacc-labeled", "TRDACC", Pattern9()),
    ];
    [GeneratedRegex("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Pattern0();
    [GeneratedRegex("\\b[0-9a-fA-F]{32}\\b", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Pattern1();
    [GeneratedRegex("\\b[A-Za-z][-\\.][0-9]{1,20}\\b", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Pattern2();
    [GeneratedRegex("[\\p{L}\\p{N}._%+-]+@[\\p{L}\\p{N}.-]+\\.[\\p{L}]{2,24}", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Pattern3();
    [GeneratedRegex("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Pattern4();
    [GeneratedRegex("\\b(?:ghp_|github_pat_|sk-)[A-Za-z0-9_-]{16,}", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Pattern5();
    [GeneratedRegex("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", RegexOptions.CultureInvariant, 100)]
    private static partial Regex Pattern6();
    [GeneratedRegex("\\b(?:\u0418\u041d\u041d|inn)\\s*[:=]?\\s*[0-9]{10,12}\\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 100)]
    private static partial Regex Pattern7();
    [GeneratedRegex("\\b(?:\u041a\u041f\u041f|kpp)\\s*[:=]?\\s*[0-9]{9}\\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 100)]
    private static partial Regex Pattern8();
    [GeneratedRegex("\\btrdacc\\s*[:=]\\s*[A-Za-z0-9_.-]{1,64}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 100)]
    private static partial Regex Pattern9();
}
