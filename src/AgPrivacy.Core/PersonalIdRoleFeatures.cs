namespace AgPrivacy;

/// <summary>Role and distance features shared by the version-two trainer and stream observer.</summary>
internal static class PersonalIdRoleFeatures
{
    internal const int FirstHashedBucket = 20;
    private static readonly string[] Person =
        ["user", "customer", "client", "employee", "staff", "person", "member", "subscriber", "holder", "individual", "agent",
         "пользовател", "клиент", "сотрудник", "работник", "владел", "участник", "подписчик", "посетител", "персонал", "человек", "физлиц"];
    private static readonly string[] Identity =
        ["id", "identifier", "identity", "number", "code", "key", "reference", "mark", "badge", "record", "profile", "payroll", "account",
         "идентификатор", "номер", "код", "ключ", "шифр", "табельн", "досье", "карточк", "запис", "метк", "профил", "имя"];
    private static readonly string[] Object =
        ["operation", "request", "event", "action", "ticket", "session", "job", "task", "cache", "batch", "transaction", "export",
         "entry", "sync", "route", "process", "device", "endpoint", "config", "database",
         "операци", "запрос", "событи", "действи", "задан", "задач", "тикет", "сесси", "запис", "пакет", "процесс",
         "выгрузк", "синхронизац", "маршрут", "транзакц", "биллинг", "устройств"];
    private static readonly string[] Container = ["log", "directory", "registry", "audit", "журнал", "реестр", "справочник", "аудит"];

    private static readonly string[] DirectPersonalLabels =
        ["user id", "customer identifier", "employee code", "employee id", "staff id",
         "идентификатор пользователя", "код сотрудника", "табельный номер", "номер участника"];

    /// <summary>Recognize a direct personal identifier label before the candidate.</summary>
    internal static bool IsExplicitPersonalLabel(ReadOnlySpan<char> context)
    {
        var label = context.TrimEnd().TrimEnd(':').TrimEnd('=').TrimEnd();
        foreach (string phrase in DirectPersonalLabels)
        {
            if (!label.EndsWith(phrase, StringComparison.OrdinalIgnoreCase)) continue;
            int start = label.Length - phrase.Length;
            if (start == 0 || !char.IsLetterOrDigit(label[start - 1])) return true;
        }
        return false;
    }

    /// <summary>Record distance to the candidate, and whether a person's role is linked to an identifier or a different object.</summary>
    internal static void Add(ReadOnlySpan<char> left, ReadOnlySpan<char> right, Span<int> features, ref int count)
    {
        var before = Inspect(left, before: true);
        var after = Inspect(right, before: false);
        int person = Math.Min(before.Person, after.Person);
        int identity = Math.Min(before.Identity, after.Identity);
        int obj = Math.Min(before.Object, after.Object);
        if (before.Person <= 3) features[count++] = 6;
        if (after.Person <= 3) features[count++] = 7;
        if (before.Identity <= 2) features[count++] = 8;
        if (after.Identity <= 2) features[count++] = 9;
        if (obj <= 3) features[count++] = 10;
        if (person <= 5 && identity <= 4) features[count++] = 11;
        if (person <= 3 && person < obj) features[count++] = 12;
        if (obj <= 3 && obj < person) features[count++] = 13;
        if (person <= 3 && identity <= 3 && obj > 3) features[count++] = 14;
        if (person <= 5 && (before.Container < int.MaxValue || after.Container < int.MaxValue)) features[count++] = 15;
        if (person <= 3 && obj <= 3) features[count++] = 16;
        if (before.Person <= 3 && before.Identity <= 2 && before.Object > before.Person) features[count++] = 17;
        if (after.Person <= 3 && after.Identity <= 2 && after.Object > after.Person) features[count++] = 18;
        if (obj <= 3 && person == int.MaxValue) features[count++] = 19;
    }

    /// <summary>Find the closest word per role, counting from the candidate on either side.</summary>
    private static Distances Inspect(ReadOnlySpan<char> clause, bool before)
    {
        int person = int.MaxValue, identity = int.MaxValue, obj = int.MaxValue, container = int.MaxValue;
        int offset = 0, wordIndex = 0;
        while (PersonalIdShadow.TryWord(clause, ref offset, out var word))
        {
            wordIndex++;
            if (Matches(word, Person) && (before || person == int.MaxValue)) person = wordIndex;
            if (Matches(word, Identity) && (before || identity == int.MaxValue)) identity = wordIndex;
            if (Matches(word, Object) && (before || obj == int.MaxValue)) obj = wordIndex;
            if (Matches(word, Container) && (before || container == int.MaxValue)) container = wordIndex;
        }
        if (!before) return new(person, identity, obj, container);
        return new(Reverse(person), Reverse(identity), Reverse(obj), Reverse(container));

        int Reverse(int index) => index == int.MaxValue ? index : wordIndex - index + 1;
    }

    /// <summary>Check English words and inflected Russian stems without creating substrings.</summary>
    private static bool Matches(ReadOnlySpan<char> word, string[] cues)
    {
        foreach (string cue in cues)
        {
            if (cue[0] < 'а' ? word.Equals(cue, StringComparison.OrdinalIgnoreCase)
                : word.StartsWith(cue, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private readonly record struct Distances(int Person, int Identity, int Object, int Container);
}
