using System.Text;
using System.Text.Json;

namespace AgPrivacy;

/// <summary>Mask a CSV table or an XML document incrementally using the same typed replacements as stream-log.</summary>
public sealed partial class StructuredPrivacyMasker(PrivacyPolicy policy, Pseudonymizer aliases)
{
    private const int UnitChars = 262144;
    private const int FieldLimit = 4096;
    private static readonly UTF8Encoding InputUtf8 = new(true, true);
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly TextRedactor redactor = new(aliases, policy, null);

    /// <summary>Read one header and apply its field rules to every following record, by column position.</summary>
    public async Task<StreamMaskResult> MaskCsvAsync(Stream input, Stream output, char delimiter = ',',
        TextWriter? journal = null, CancellationToken cancellationToken = default)
    {
        if (delimiter is not (',' or ';' or '\t')) throw new ArgumentException("invalid-csv-delimiter");
        using var reader = new StreamReader(input, InputUtf8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        await using var writer = new StreamWriter(output, Utf8, leaveOpen: true);
        var csv = new CsvRecords(reader, delimiter, UnitChars, FieldLimit);
        var state = new State(this, journal);
        if (await csv.ReadAsync(cancellationToken).ConfigureAwait(false) is not { } header) return state.Result();

        var rules = new string?[header.Count];
        var preserveGuid = new bool[header.Count];
        for (int i = 0; i < header.Count; i++)
        {
            string field = header[i].Trim();
            rules[i] = FieldRule(field);
            preserveGuid[i] = IsCorrelation(field);
            string? contact = JsonFieldNames.ContactRule(field);
            if (contact is not null)
                header[i] = state.Mask(header[i], contact == "KEY_EMAIL" ? "EMAIL" : "PHONE");
        }
        await WriteCsvAsync(writer, header, delimiter, cancellationToken).ConfigureAwait(false);
        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);

        while (await csv.ReadAsync(cancellationToken).ConfigureAwait(false) is { } row)
        {
            if (row.Count != rules.Length) throw new InvalidDataException("invalid-csv-width");
            for (int i = 0; i < row.Count; i++)
                row[i] = state.Mask(row[i], rules[i], preserveGuid[i]);
            await WriteCsvAsync(writer, row, delimiter, cancellationToken).ConfigureAwait(false);
            await state.WriteJournalAsync(cancellationToken).ConfigureAwait(false);
            if (state.ShouldFlush()) await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        await state.WriteJournalAsync(cancellationToken).ConfigureAwait(false);
        return state.Result();
    }

    /// <summary>Serialize a whole record after validation, preserving cell values across CSV escaping.</summary>
    private static Task WriteCsvAsync(TextWriter writer, List<string> cells, char delimiter, CancellationToken cancellationToken)
    {
        var row = new StringBuilder();
        for (int i = 0; i < cells.Count; i++)
        {
            if (i != 0) row.Append(delimiter);
            string value = cells[i];
            if (value.AsSpan().IndexOfAny(delimiter, '"', '\r') < 0 && !value.Contains('\n')) row.Append(value);
            else row.Append('"').Append(value.Replace("\"", "\"\"", StringComparison.Ordinal)).Append('"');
        }
        row.Append("\r\n");
        return writer.WriteAsync(row.ToString().AsMemory(), cancellationToken);
    }

    /// <summary>Resolve a declared schema field first, then exact common aliases for exports.</summary>
    private string? FieldRule(string field)
    {
        string normalized = PrivacyPolicy.NormalizeField(field);
        string? type = policy.FieldType(field);
        if (type is not null && type != "IDENTIFIER") return type;
        string? label = DisplayMaskRules.ForField(field, type ?? "TEXT");
        if (label != "TEXT" && normalized is not ("date" or "дата")) return label;
        return normalized switch
        {
            "customername" or "customerfullname" or "contactname" or "фиоклиента" or "имяклиента" => "PERSON",
            "emailaddress" or "customeremail" or "contactemail" or "электроннаяпочта" => "EMAIL",
            "phonenumber" or "contactphone" or "customerphone" or "номертелефона" => "PHONE",
            "ip" or "ipaddress" or "sourceip" or "destinationip" or "clientip" or "remoteip" => "IP",
            "номерпаспорта" or "идентификаторклиента" => "IDENTIFIER",
            "иннфизлица" or "иннклиента" => "INN",
            "датарожденияклиента" => "DATE",
            _ => type
        };
    }

    /// <summary>Use a narrow exemption that never suppresses secret rules.</summary>
    private static bool IsCorrelation(string field) =>
        field.Equals("trace.id", StringComparison.OrdinalIgnoreCase) || field.Equals("MasterId", StringComparison.OrdinalIgnoreCase);

    private sealed class State(StructuredPrivacyMasker owner, TextWriter? journal)
    {
        private readonly Queue<string> order = new();
        private readonly HashSet<string> seen = new(StringComparer.Ordinal);
        private readonly List<StreamReplacement> pending = [];
        private long lastFlush = Environment.TickCount64;
        private readonly Dictionary<string, long> replacementsByType = new(StringComparer.Ordinal);
        private long replacements;

        /// <summary>Expose complete rule counts independently of journal settings.</summary>
        internal StreamMaskResult Result() => new(replacements, 0)
        {
            ReplacementsByType = replacementsByType
        };

        /// <summary>Flush a ready prefix during sustained input without flushing every value.</summary>
        internal bool ShouldFlush()
        {
            long now = Environment.TickCount64;
            if (now - lastFlush < 10) return false;
            lastFlush = now;
            return true;
        }

        /// <summary>Apply a whole-value schema rule or fall back to recognized spans inside the value.</summary>
        internal string Mask(string value, string? rule, bool preserveGuid = false)
        {
            if (string.IsNullOrWhiteSpace(value)) return value;
            if (rule is not null) return Replace(value, new(0, value.Length, rule));

            var spans = owner.redactor.FindTypedLogSpans(value);
            if (preserveGuid && Guid.TryParse(value, out _))
                spans.RemoveAll(span => span.Type == "GUID");
            if (spans.Count == 0) return value;

            var output = new StringBuilder(value.Length);
            int offset = 0;
            foreach (var span in TextRedactor.MergeSpans(spans))
            {
                output.Append(value, offset, span.Start - offset).Append(Replace(value, span));
                offset = span.Start + span.Length;
            }
            return output.Append(value, offset, value.Length - offset).ToString();
        }

        /// <summary>Count a replacement and remember at most 4096 recently journaled mappings.</summary>
        private string Replace(string value, EntitySpan span)
        {
            var (rule, replacement, id) = owner.redactor.MaskSpan(value, span, display: true, substitute: true,
                journal: journal is not null);
            replacements++;
            replacementsByType[rule] = replacementsByType.GetValueOrDefault(rule) + 1;
            if (id is not null && seen.Add(id))
            {
                order.Enqueue(id);
                if (order.Count > 4096) seen.Remove(order.Dequeue());
                pending.Add(new(id, rule, replacement));
            }
            return replacement;
        }

        /// <summary>Append only keyed IDs, rule names and masked values.</summary>
        internal async Task WriteJournalAsync(CancellationToken cancellationToken)
        {
            if (journal is null) return;
            foreach (var record in pending)
            {
                string line = JsonSerializer.Serialize(record, PrivacyJsonContext.Default.StreamReplacement);
                await journal.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
            }
            pending.Clear();
        }
    }
}
