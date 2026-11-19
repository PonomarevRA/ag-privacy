namespace AgPrivacy;

/// <summary>Remember exact contextual name spans in bounded, in-process memory for one stream.</summary>
internal sealed class RecentStreamNames : IDisposable
{
    private const int Capacity = 64;
    private readonly Queue<char[]> values = new();

    /// <summary>Learn multiword names from contextual rules, excluding free-model predictions and escaped values.</summary>
    internal void Learn(string text, List<EntitySpan> spans, int from)
    {
        foreach (var span in spans)
        {
            if (span.Start < from || span.Type != "PERSON" || span.Priority < 50 || span.Length is < 5 or > 96 ||
                span.UrlEncoded || span.JsonEscapeLayers != 0) continue;
            var value = text.AsSpan(span.Start, span.Length);
            if (!IsName(value) || values.Any(existing => text.AsSpan(span.Start, span.Length).SequenceEqual(existing))) continue;
            if (values.Count == Capacity) Array.Clear(values.Dequeue());
            values.Enqueue(value.ToArray());
        }
    }

    /// <summary>Match exact whole names, without extending an existing rule's span.</summary>
    internal void AddMatches(string text, int from, List<EntitySpan> spans)
    {
        foreach (char[] value in values)
        {
            for (int search = from; search <= text.Length - value.Length;)
            {
                int found = text.AsSpan(search).IndexOf(value, StringComparison.Ordinal);
                if (found < 0) break;
                int first = search + found;
                int end = first + value.Length;
                search = end;
                if ((first > 0 && IsWord(text[first - 1])) || (end < text.Length && IsWord(text[end]))) continue;
                if (LogPersonContext.IsTechnicalValue(text, from, first)) continue;
                if (spans.Exists(span => span.Start < end && span.Start + span.Length > first &&
                    (span.Type != "PERSON" || (span.Start <= first && span.Start + span.Length >= end)))) continue;
                if (spans.Count >= PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
                spans.Add(new(first, value.Length, "PERSON", 45));
            }
        }
    }

    /// <summary>Accept only a two- or three-word spelling composed of letters and common name punctuation.</summary>
    private static bool IsName(ReadOnlySpan<char> value)
    {
        int spaces = 0;
        foreach (char ch in value)
        {
            if (ch == ' ') spaces++;
            else if (!char.IsLetter(ch) && ch is not ('-' or '\'' or '’')) return false;
        }
        return spaces is 1 or 2;
    }

    private static bool IsWord(char ch) => char.IsLetterOrDigit(ch) || ch is ('_' or '-' or '\'' or '’');

    /// <summary>Clear the retained character arrays when the stream ends.</summary>
    public void Dispose()
    {
        while (values.TryDequeue(out char[]? value)) Array.Clear(value);
    }
}
