using System.Collections.Frozen;
using System.Text.Json;

namespace AgPrivacy;

/// <summary>Exact property names whose display values can skip heuristic person detection.</summary>
public sealed class DisplayFieldExceptions
{
    public static DisplayFieldExceptions Default { get; } = new(new[] { "isin", "ticker" });

    private readonly FrozenSet<string> fields;

    private DisplayFieldExceptions(IEnumerable<string> fields) =>
        this.fields = fields.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public IReadOnlySet<string> Fields => fields;

    /// <summary>Read a bounded list of field names. Dots are literal, as in flattened ECS properties.</summary>
    public static DisplayFieldExceptions Compile(JsonElement list)
    {
        if (list.ValueKind != JsonValueKind.Array || list.GetArrayLength() > 32)
            throw new ArgumentException("invalid-display-field-exceptions");

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in list.EnumerateArray())
        {
            string? name = item.ValueKind == JsonValueKind.String ? item.GetString() : null;
            if (name is null || name.Length is 0 or > 96 || !char.IsLetter(name[0]) && name[0] != '_' ||
                name.Any(c => !char.IsLetterOrDigit(c) && c is not ('_' or '.' or '-')) || !names.Add(name))
                throw new ArgumentException("invalid-display-field-exceptions");
        }
        return new(names);
    }

    internal bool Contains(string? field) => field is not null && fields.Contains(field);
}
