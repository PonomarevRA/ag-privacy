using System.Diagnostics;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Source-generated regex проверяют полную неделимую строку; таймаут никогда не разрешает raw fallback.</summary>
public static class RegexDetector
{
    internal const int MatchPriority = 100;

    /// <summary>Check for a compiled pattern of one type without collecting all matching spans.</summary>
    internal static bool HasMatch(string text, string type, bool wholeValue = false)
    {
        foreach (var rule in GeneratedRules.All)
        {
            if (rule.Type != type) continue;
            if (!wholeValue)
            {
                if (rule.Pattern.IsMatch(text)) return true;
                continue;
            }

            var match = rule.Pattern.Match(text);
            if (match.Success && match.Length == text.Length) return true;
        }
        return false;
    }

    public static IReadOnlyList<EntitySpan> Find(string text) => Find(text, type: null);

    /// <summary>Collect only the requested entity type while retaining the usual scan limits.</summary>
    internal static List<EntitySpan> Find(string text, string? type)
    {
        var spans = new List<EntitySpan>();
        var watch = Stopwatch.StartNew();
        foreach (var rule in GeneratedRules.All)
        {
            if (type is not null && rule.Type != type) continue;
            foreach (Match match in rule.Pattern.Matches(text))
            {
                if (watch.ElapsedMilliseconds > 250 || spans.Count >= PrivacyLimits.Entities) throw new InvalidOperationException("analysis-limit");
                if (match.Length > 0) spans.Add(new(match.Index, match.Length, rule.Type, MatchPriority));
            }
            if (watch.ElapsedMilliseconds > 250) throw new InvalidOperationException("analysis-limit");
        }
        return spans;
    }
}

/// <summary>Тип и скомпилированный при сборке распознаватель; значения не исполняют конфигурацию.</summary>
public sealed record RegexRule(string Id, string Type, Regex Pattern);
