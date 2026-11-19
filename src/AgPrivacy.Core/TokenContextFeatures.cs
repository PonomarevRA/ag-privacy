namespace AgPrivacy;

/// <summary>Capture credential purpose and competing infrastructure context without inspecting the value itself.</summary>
internal static class TokenContextFeatures
{
    private static readonly string[] Credential =
        ["credential", "token", "secret", "password", "passphrase", "bearer", "секрет", "токен", "парол"];
    private static readonly string[] Purpose =
        ["signature", "privilege", "authentication", "authorization", "decrypt", "encrypt", "подпис", "аутентификац", "авторизац"];
    private static readonly string[] Lifetime =
        ["rotated", "revoked", "expired", "renewed", "срок", "отозван", "истек", "замен"];
    private static readonly string[] Reference =
        ["trace", "identifier", "reference", "checksum", "hash", "correlation", "идентификатор", "трасс", "сумм", "хэш"];
    private static readonly string[] Infrastructure =
        ["worker", "pipeline", "dashboard", "profiling", "endpoint", "job", "task", "задан", "задач", "событи", "корреляц"];

    /// <summary>Encode credential-specific features into reserved buckets following the generic text features.</summary>
    internal static int Extract(ReadOnlySpan<char> text, int start, int length, Span<int> features, bool specialized)
    {
        int count = PersonalIdShadow.Extract(text, start, length, features, legacy: true);
        if (!specialized || count == 0) return count;

        // Compress generic buckets away from the slots used for the role indicators.
        const int first = 16;
        for (int i = 1; i < count; i++)
            features[i] = first + (features[i] - 1) % (PersonalIdShadow.Buckets - first);

        int end = start + length;
        var left = text[Math.Max(0, start - 60)..start];
        var right = text[end..Math.Min(text.Length, end + 60)];
        left = left[(left.LastIndexOfAny(";\r\n!?") + 1)..];
        int separator = right.IndexOfAny(";\r\n!?");
        if (separator >= 0) right = right[..separator];
        bool credential = HasCue(left, Credential) || HasCue(right, Credential);
        bool purpose = HasCue(left, Purpose) || HasCue(right, Purpose);
        bool lifetime = HasCue(left, Lifetime) || HasCue(right, Lifetime);
        bool reference = HasCue(left, Reference) || HasCue(right, Reference);
        bool infrastructure = HasCue(left, Infrastructure) || HasCue(right, Infrastructure);
        Add(credential, 1, features, ref count);
        Add(purpose, 2, features, ref count);
        Add(lifetime, 3, features, ref count);
        Add(reference, 4, features, ref count);
        Add(infrastructure, 5, features, ref count);
        Add((credential || purpose || lifetime) && !reference, 6, features, ref count);
        Add(reference && (credential || purpose), 7, features, ref count);
        return count;
    }

    /// <summary>Respect the fixed allocation even when the generic features fill the context window.</summary>
    private static void Add(bool present, int id, Span<int> features, ref int count)
    {
        if (present && count < features.Length) features[count++] = id;
    }

    /// <summary>Locate words or Russian stems without allocating strings.</summary>
    private static bool HasCue(ReadOnlySpan<char> text, string[] cues)
    {
        int offset = 0;
        while (PersonalIdShadow.TryWord(text, ref offset, out var word))
        {
            foreach (string cue in cues)
            {
                if (cue[0] < 'а' ? word.Equals(cue, StringComparison.OrdinalIgnoreCase)
                    : word.StartsWith(cue, StringComparison.OrdinalIgnoreCase)) return true;
            }
        }
        return false;
    }
}
