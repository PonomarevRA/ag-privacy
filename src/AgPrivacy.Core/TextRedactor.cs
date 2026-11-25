using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>Одна полная строка до chunking; heuristic не является гарантией отсутствия ПДн.</summary>
public sealed partial class TextRedactor(Pseudonymizer aliases, PrivacyPolicy policy, IPersonDetector? persons)
{
    private readonly IPersonDetector? proseModel;

    /// <summary>Use a second model only as a fallback for typed log message candidates.</summary>
    internal TextRedactor(Pseudonymizer aliases, PrivacyPolicy policy, IPersonDetector? persons, IPersonDetector? proseModel)
        : this(aliases, policy, persons) => this.proseModel = proseModel;

    private readonly IPersonDetector? structuredDetector;
    private readonly LogAnalysisMode? analysisMode;

    /// <summary>Route prose and structured detectors independently. Null mode keeps the legacy typed-log path.</summary>
    internal TextRedactor(Pseudonymizer aliases, PrivacyPolicy policy, IPersonDetector? persons, IPersonDetector? proseModel,
        IPersonDetector? structuredDetector, LogAnalysisMode analysisMode)
        : this(aliases, policy, persons, proseModel)
    {
        this.structuredDetector = structuredDetector;
        this.analysisMode = analysisMode;
    }

    private static readonly Regex Parameters = new(@"[?&](?<name>[^=&#\s]{1,128})=(?<value>[^&#\s]*)", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));
    private static readonly Regex RoutedParameters = new("""[?&](?<name>[^=&#?\s"'<>\\{}]{1,128})=(?<value>[^&#\s"'<>\\{}]*)""",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));
    private static readonly Regex Labeled = new(@"(?<name>[\p{L}_][\p{L}\p{N}_-]{0,95})\s*[:=]\s*(?:""(?<quoted>[^""\r\n]*)""|«(?<quoted>[^»\r\n]*)»|(?<value>[^\s&;,<>{}\r\n]+))", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(100));

    /// <summary>Объединяет исходные интервалы по приоритету без placeholder-restore и его обходов.</summary>
    public (string Text, int Count) Redact(string text)
    {
        var spans = FindSpans(text, policy, persons ?? throw new InvalidOperationException("model-required"));
        return Render(text, spans, display: false);
    }

    /// <summary>Mask recognized spans in a log message while preserving text outside them.</summary>
    internal (string Text, int Count) RedactLogMessage(string text, DisplayFieldExceptions exceptions, Dictionary<string, int>? replacementsByType = null, List<MaskHighlight>? highlights = null)
    {
        var spans = FindSpans(text, policy, persons, logMessage: true);
        TransliteratedPersonNames.AddMessageNames(text, 0, text.Length, spans);
        LabelledCompoundPersonNames.Add(text, 0, text.Length, spans);
        ContextualLogPersonModel.Add(text, 0, text.Length, spans, persons, proseModel);
        LogMasking.AddSpans(text, spans, persons, exceptions);
        LogNetworkAddresses.Add(text, spans);
        LogPersonContext.RemoveTechnicalSpans(text, 0, text.Length, spans);
        if (spans.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
        return Render(text, spans, display: true, replacementsByType, highlights: highlights);
    }

    /// <summary>Mask UUID tokens while leaving complete MasterId string values intact.</summary>
    internal (string Text, int Count) RedactGuids(string text)
    {
        var spans = RegexDetector.Find(text, "GUID");
        RemoveMasterIds(text, spans);
        return Render(text, spans, display: true);
    }

    /// <summary>Mask detected log fragments and count the rule used for each emitted marker.</summary>
    internal (string Text, int Count) RedactTypedLog(string text, Dictionary<string, int> replacementsByType, List<MaskHighlight>? highlights = null)
    {
        var spans = FindTypedLogSpans(text);
        return Render(text, spans, display: true, replacementsByType, substitute: true, highlights);
    }

    /// <summary>Collect the same typed rules for an in-memory message or a bounded stream window.</summary>
    internal List<EntitySpan> FindTypedLogSpans(string text, List<LogMessageRange>? messages = null)
    {
        if (analysisMode is not null)
            return FindRoutedTypedLogSpans(text, messages, analysisMode.Value);
        // The name model mistakes property labels and gRPC method names for names in structured logs.
        // Named rules cover quoted person fields, and contextual lowercase detection still runs below.
        Match firstProperty = QuotedPropertyStarts().Match(text);
        var nestedNames = new List<EntitySpan>();
        bool nestedStructure = NestedJsonMessagePersonNames.Add(text, nestedNames, policy);
        bool structured = firstProperty.Success || nestedStructure;
        var spans = FindSpans(text, policy, structured ? null : persons, logMessage: true, includeGuids: true);
        RemoveMasterIds(text, spans);
        spans.AddRange(nestedNames);
        if (!structured)
        {
            TransliteratedPersonNames.AddMessageNames(text, 0, text.Length, spans);
            LabelledCompoundPersonNames.Add(text, 0, text.Length, spans);
            ContextualLogPersonModel.Add(text, 0, text.Length, spans, persons, proseModel);
            LogSensitiveFields.AddBirthDates(text, 0, text.Length, spans);
            LogSensitiveFields.AddInlineSecrets(text, 0, text.Length, spans);
        }
        AddJsonPropertySpans(text, firstProperty, spans, messages);
        LogSensitiveFields.AddNumericSecrets(text, spans);
        LogMasking.AddSpans(text, spans, persons, policy.DisplayFieldExceptions);
        LogNetworkAddresses.Add(text, spans);
        if (!structured) LogPersonContext.RemoveTechnicalSpans(text, 0, text.Length, spans);
        TransliteratedPersonNames.PreserveTechnicalLogins(text, spans);
        LogSensitiveFields.PreserveTraceIds(text, spans);
        if (spans.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
        return spans;
    }

    /// <summary>Exempt only the UUID occurrence used as a complete MasterId value.</summary>
    private static void RemoveMasterIds(string text, List<EntitySpan> spans)
    {
        if (!spans.Exists(span => span.Type == "GUID")) return;

        var preserved = new HashSet<(int Start, int Length)>();
        foreach (Match property in MasterIdProperties().Matches(text))
        {
            Group group = property.Groups["value"];
            ReadOnlySpan<char> value = group.ValueSpan.TrimStart();
            int start = group.Index + group.Length - value.Length;
            value = value.TrimEnd();
            if (!Guid.TryParse(value, out _)) continue;
            if (value[0] is '{' or '(')
            {
                value = value[1..^1];
                start++;
            }
            preserved.Add((start, value.Length));
        }

        spans.RemoveAll(span => span.Type == "GUID" && preserved.Contains((span.Start, span.Length)));
    }

    // Use the same quote token for each delimiter to support plain and escaped JSON without decoding the log.
    [GeneratedRegex("""(?<!\\)(?<quote>\\*")MasterId\k<quote>\s*:\s*\k<quote>(?<value>[^"\\\r\n]{1,64})\k<quote>""",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, 100)]
    private static partial Regex MasterIdProperties();

    /// <summary>Use named rules for quoted JSON fields without decoding or reserializing the log.</summary>
    private void AddJsonPropertySpans(string text, Match firstProperty, List<EntitySpan> spans, List<LogMessageRange>? messages,
        NestedJsonMessagePersonNames.Sink? routed = null)
    {
        var watch = Stopwatch.StartNew();
        for (Match property = firstProperty; property.Success; property = property.NextMatch())
        {
            if (watch.ElapsedMilliseconds > 250 || spans.Count >= PrivacyLimits.Entities)
                throw new InvalidOperationException("analysis-limit");

            string name = property.Groups["name"].Value;
            string? type = policy.FieldType(name);
            string rule = type == "SECRET" ? type : DisplayMaskRules.ForField(name, type ?? "TEXT");
            bool logMessage = name is "message" or "event.original";
            int delimiterSlashes = property.Groups["quote"].Length - 1;
            bool loginField = delimiterSlashes == 0 && TransliteratedPersonNames.LoginField().IsMatch(name);
            if (!logMessage && !loginField && rule == "TEXT" && type is null) continue;

            int start = property.Index + property.Length;
            int end = FindClosingQuote(text, start, delimiterSlashes);
            if (end <= start) continue;
            if (rule != "TEXT" || type is not null)
                spans.Add(new(start, end - start, rule, 200));
            else if (logMessage)
            {
                if (delimiterSlashes == 0) messages?.Add(new(start, end));
                IPersonDetector? spanModel = routed is null ? persons : null;
                IPersonDetector? spanProse = routed is null ? proseModel : null;
                JsonMessagePersonNames.Add(text, start, end - start, delimiterSlashes == 0, spans, policy.DisplayFieldExceptions, spanModel, spanProse);
            }
            else if (loginField)
                TransliteratedPersonNames.AddJsonLogin(text, property.Groups["name"].Index, start, end - start, spans);
        }
    }

    /// <summary>Find a closing quote at the property's escape depth, skipping quotes embedded in its value.</summary>
    private static int FindClosingQuote(string text, int start, int delimiterSlashes)
    {
        int escapedSlashPair = 2 * (delimiterSlashes + 1);
        for (int quote = text.IndexOf('"', start); quote >= 0; quote = text.IndexOf('"', quote + 1))
        {
            int tokenStart = quote;
            while (tokenStart > start && text[tokenStart - 1] == '\\') tokenStart--;
            int slashes = quote - tokenStart;
            // A quote at a shallower depth ends the enclosing text, so the field has no complete value.
            if (slashes < delimiterSlashes) break;
            // A pair of escaped backslashes belongs to the value and does not escape the quote.
            if ((slashes - delimiterSlashes) % escapedSlashPair == 0) return quote - delimiterSlashes;
        }
        return -1;
    }

    [GeneratedRegex("""(?<!\\)(?<quote>\\*")(?<name>[\p{L}_][\p{L}\p{N}_.-]{0,95})\k<quote>\s*:\s*\k<quote>""",
        RegexOptions.CultureInvariant, 100)]
    private static partial Regex QuotedPropertyStarts();

    /// <summary>Merge overlapping detections and copy the untouched parts of the original string.</summary>
    private (string Text, int Count) Render(string text, List<EntitySpan> spans, bool display, Dictionary<string, int>? replacementsByType = null, bool substitute = false, List<MaskHighlight>? highlights = null)
    {
        if (spans.Count == 0) return (text, 0);
        var chosen = MergeSpans(spans);
        var output = new StringBuilder(); int offset = 0;
        int replacementCount = 0;
        foreach (var span in chosen)
        {
            output.Append(text, offset, span.Start - offset);
            var (rule, replacement, _) = MaskSpan(text, span, display, substitute);
            int replacementStart = output.Length;
            output.Append(replacement);
            if (!substitute || !text.AsSpan(span.Start, span.Length).SequenceEqual(replacement))
            {
                replacementCount++;
                highlights?.Add(new(replacementStart, replacement.Length));
                if (replacementsByType is not null)
                    replacementsByType[rule] = replacementsByType.GetValueOrDefault(rule) + 1;
            }
            offset = span.Start + span.Length;
        }
        output.Append(text, offset, text.Length - offset);
        return (output.ToString(), replacementCount);
    }

    /// <summary>Sort and merge detected spans without dropping sensitive text from overlaps.</summary>
    internal static List<EntitySpan> MergeSpans(List<EntitySpan> spans)
    {
        spans.Sort((a,b) => { int start = a.Start.CompareTo(b.Start); return start != 0 ? start : b.Length.CompareTo(a.Length); });
        var chosen = new List<EntitySpan>();
        foreach (var span in spans)
        {
            if (chosen.Count == 0 || span.Start >= chosen[^1].Start + chosen[^1].Length)
            {
                chosen.Add(span); continue;
            }
            // Preserve the union of every detected interval: priority selects a label, never un-masks its neighbours.
            EntitySpan previous = chosen[^1];
            int end = Math.Max(previous.Start + previous.Length, span.Start + span.Length);
            EntitySpan winner = span.Priority > previous.Priority ? span : previous;
            string type = previous.Type == "SECRET" || span.Type == "SECRET" ? "SECRET" : winner.Type;
            bool decode = winner.UrlEncoded && winner.Start == previous.Start && winner.Start + winner.Length == end;
            // An escape count belongs to an exact source interval, not to a wider union.
            int layers = decode ? winner.JsonEscapeLayers : 0;
            if (!decode && type is ("PERSON" or "DATE" or "SECRET"))
            {
                if (previous.Start + previous.Length == end) layers = previous.JsonEscapeLayers;
                if (span.Start == previous.Start && span.Start + span.Length == end)
                    layers = Math.Max(layers, span.JsonEscapeLayers);
            }
            chosen[^1] = new(previous.Start, end - previous.Start, type, Math.Max(previous.Priority, span.Priority), decode)
                {
                    JsonEscapeLayers = layers,
                    JsonNumber = winner.JsonNumber && winner.Start == previous.Start && winner.Start + winner.Length == end
                };
        }
        return chosen;
    }

    /// <summary>Apply the selected mask and optionally compute an opaque identifier for the journal.</summary>
    internal (string Rule, string Replacement, string? Id) MaskSpan(string text, EntitySpan span,
        bool display, bool substitute, bool journal = false)
    {
        string raw = text.Substring(span.Start, span.Length);
        string value = span.UrlEncoded ? DecodeParameter(raw) : raw;
        string type = span.Type;
        string rule = type;
        if (substitute)
        {
            if (type == "IDENTIFIER" && SoftPartFormats.IsAgreementValue(value)) rule = "AGREEMENT";
            if (type == "AGREEMENT") type = "IDENTIFIER";
            if (type is "DATE" or "TIN") type = "TEXT";
        }
        string replacement;
        if (substitute)
        {
            if (type == "IP") replacement = "[IP]";
            else if (span.JsonNumber) replacement = "0";
            else if (span.JsonEscapeLayers > 0 && span.UrlEncoded)
                replacement = ReplaceEscapedQuery(raw, span.JsonEscapeLayers, type);
            else if (span.JsonEscapeLayers > 0)
                replacement = JsonMessagePersonNames.ReplaceEscaped(value, span.JsonEscapeLayers, type, aliases);
            else replacement = aliases.ReplaceWithShape(type, value);
            if (span.UrlEncoded && span.JsonEscapeLayers == 0) replacement = Uri.EscapeDataString(replacement);
        }
        else if (display) replacement = aliases.ReplaceForDisplay(type, value, rule);
        else replacement = aliases.Replace(type, value);

        string? id = null;
        if (journal)
        {
            string codec = span.JsonEscapeLayers.ToString(System.Globalization.CultureInfo.InvariantCulture);
            id = aliases.StreamJournalId(type, string.Concat(rule, "\\0", span.UrlEncoded ? "url" : "raw", "\\0", codec, "\\0", raw));
        }
        return (rule, replacement, id);
    }

    /// <summary>Find formal, labeled, URL and optional person-name spans before choosing a mask.</summary>
    internal static List<EntitySpan> FindSpans(string text, PrivacyPolicy policy, IPersonDetector? persons, bool logMessage = false, bool includeGuids = false, bool skipParameters = false)
    {
        var spans = new List<EntitySpan>(RegexDetector.Find(text));
        if (logMessage && !includeGuids) spans.RemoveAll(span => span.Type == "GUID");
        if (!skipParameters) AddParameters(text, spans, policy, onlyKnown: logMessage);
        foreach (Match match in Labeled.Matches(text))
        {
            Group name = match.Groups["name"];
            if (skipParameters && IsQueryName(text, name.Index)) continue;
            string? type = policy.FieldType(name.Value);
            Group value = match.Groups["quoted"].Success ? match.Groups["quoted"] : match.Groups["value"];
            if (logMessage && match.Groups["name"].Value.Equals("authorization", StringComparison.OrdinalIgnoreCase) &&
                (value.Value.Equals("Bearer", StringComparison.OrdinalIgnoreCase) ||
                 value.Value.Equals("Basic", StringComparison.OrdinalIgnoreCase) ||
                 CredentialsRedactor.ContainsAuthorizationToken(value.Value))) continue;
            // In a service-account phrase, "account: login=..." is an assignment, not an account number.
            if (logMessage && type == "ACCOUNT" && match.Groups["name"].Value.Equals("account", StringComparison.OrdinalIgnoreCase) &&
                TransliteratedPersonNames.IsTechnicalLoginAssignment(text, value.Index, value.Length)) continue;
            if (logMessage && type == "KLOGIN" &&
                TransliteratedPersonNames.IsTechnicalLoginValue(text, match.Index, value.Index, value.Length)) continue;
            if (type is not null && value.Length > 0) spans.Add(new(value.Index, value.Length, type, 200));
        }
        if (persons is not null) spans.AddRange(persons.Find(text));
        if (spans.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
        foreach (var span in spans)
            if (span.Start < 0 || span.Length <= 0 || span.Start > text.Length - span.Length || !PrivacyPolicy.EntityTypes.Contains(span.Type)) throw new InvalidOperationException("invalid-span");
        return spans;
    }

    /// <summary>Декодирует имя параметра ограниченно; не доверяет package-пометкам, пришедшим с URL.</summary>
    private static void AddParameters(string text, List<EntitySpan> spans, PrivacyPolicy policy, bool onlyKnown)
    {
        foreach (Match match in Parameters.Matches(text))
        {
            string name = DecodeParameter(match.Groups["name"].Value);
            string? type = policy.FieldType(name);
            var value = match.Groups["value"];
            if (onlyKnown && type is null) continue;
            // Все непустые query values скрываются даже при неизвестном имени; исходная кодировка не возвращается.
            if (value.Length > 0) spans.Add(new(value.Index, value.Length, type ?? "TEXT", 300, true));
            if (type is null) spans.Add(new(match.Groups["name"].Index, match.Groups["name"].Length, "KEY", 300));
        }
    }

    /// <summary>Ограничивает вложенное URL-кодирование двумя проходами; остаток обрабатывается как неизвестное значение.</summary>
    private static string DecodeParameter(string value)
    {
        for (int i = 0; i < 2; i++)
        {
            string next = Uri.UnescapeDataString(value.Replace('+', ' '));
            if (next == value) break;
            value = next;
        }
        return value;
    }

    /// <summary>Collect deterministic masks and route prose and structured spans in source coordinates.</summary>
    private List<EntitySpan> FindRoutedTypedLogSpans(string text, List<LogMessageRange>? messages, LogAnalysisMode mode)
    {
        Match firstProperty = QuotedPropertyStarts().Match(text);
        var nestedNames = new List<EntitySpan>();
        var sink = new NestedJsonMessagePersonNames.Sink();
        NestedJsonMessagePersonNames.Map(text, nestedNames, policy, sink);
        bool jsonSyntax = firstProperty.Success || sink.Ranges.Count > 0;
        var spans = FindSpans(text, policy, null, logMessage: true, includeGuids: true, skipParameters: true);
        RemoveMasterIds(text, spans);
        spans.AddRange(nestedNames);
        if (!jsonSyntax)
        {
            TransliteratedPersonNames.AddMessageNames(text, 0, text.Length, spans);
            LabelledCompoundPersonNames.Add(text, 0, text.Length, spans);
            LogSensitiveFields.AddBirthDates(text, 0, text.Length, spans);
            LogSensitiveFields.AddInlineSecrets(text, 0, text.Length, spans);
        }
        AddJsonPropertySpans(text, firstProperty, spans, messages, sink);
        LogSensitiveFields.AddNumericSecrets(text, spans);
        LogMasking.AddSpans(text, spans, null, policy.DisplayFieldExceptions);
        LogNetworkAddresses.Add(text, spans);
        if (!jsonSyntax) LogPersonContext.RemoveTechnicalSpans(text, 0, text.Length, spans);

        var learned = new List<EntitySpan>();
        var queries = new List<EntitySpan>();
        RouteRegions(new(text, null, 0), sink, mode, learned, queries, [], 0);
        // A rule matched against an encoded source can run into an escaped query delimiter.
        // A valid parameter boundary is authoritative for a rule starting inside that value.
        spans.AddRange(learned);
        spans.RemoveAll(span => queries.Exists(query => span.Start >= query.Start
            && span.Start < query.Start + query.Length && span.Start + span.Length > query.Start + query.Length));
        spans.AddRange(queries);
        TransliteratedPersonNames.PreserveTechnicalLogins(text, spans);
        LogSensitiveFields.PreserveTraceIds(text, spans);
        if (spans.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
        return spans;
    }

    /// <summary>Route gaps to the prose model and structured leaves to the structured model.</summary>
    private void RouteRegions(NestedJsonMessagePersonNames.MappedText region, NestedJsonMessagePersonNames.Sink sink,
        LogAnalysisMode mode, List<EntitySpan> learned, List<EntitySpan> queries, List<EntitySpan> hits, int depth)
    {
        if (depth > 8) throw new InvalidOperationException("analysis-limit");
        IPersonDetector? model = mode == LogAnalysisMode.Structured ? null : proseModel;
        int cursor = 0;
        foreach (var (start, length) in sink.Ranges)
        {
            RouteSlice(region, cursor, start - cursor, model, learned, queries, hits);
            cursor = start + length;
        }
        RouteSlice(region, cursor, region.Text.Length - cursor, model, learned, queries, hits);

        foreach (var query in sink.Queries)
            ProjectQueries(region.Compose(query), 0, query.Text.Length, queries);
        foreach (var leaf in sink.Leaves)
        {
            var mapped = region.Compose(leaf);
            var nested = new NestedJsonMessagePersonNames.Sink();
            var nestedSpans = new List<EntitySpan>();
            NestedJsonMessagePersonNames.Map(leaf.Text, nestedSpans, policy, nested);
            if (nested.Ranges.Count > 0)
            {
                ProjectNamedPersons(mapped, nestedSpans, learned);
                RouteRegions(mapped, nested, mode, learned, queries, hits, depth + 1);
            }
            else
                RouteSlice(mapped, 0, mapped.Text.Length, mode == LogAnalysisMode.Text ? null : structuredDetector, learned, queries, hits);
        }
    }

    /// <summary>Lift authoritative field spans from embedded JSON in a decoded message leaf.</summary>
    private static void ProjectNamedPersons(NestedJsonMessagePersonNames.MappedText region,
        List<EntitySpan> fields, List<EntitySpan> output)
    {
        foreach (var field in fields)
        {
            if (field.Priority != NestedJsonMessagePersonNames.NamedPersonPriority) continue;
            int start = region.SourceOffset(field.Start);
            int length = region.SourceOffset(field.Start + field.Length) - start;
            int layers = field.JsonEscapeLayers;
            if (length != field.Length || layers != 0) layers += region.Layers;
            output.Add(field with { Start = start, Length = length, JsonEscapeLayers = layers });
        }
    }

    /// <summary>Run one detector on a logical slice and project its validated spans to the original log.</summary>
    private void RouteSlice(NestedJsonMessagePersonNames.MappedText region, int start, int length, IPersonDetector? model,
        List<EntitySpan> learned, List<EntitySpan> queries, List<EntitySpan> hits)
    {
        if (length <= 0) return;
        ProjectQueries(region, start, length, queries);
        ReadOnlySpan<char> slice = region.Text.AsSpan(start, length);
        if (model is null || !HasWord(slice)) return;
        hits.Clear();
        string piece;
        if (model is MicroPersonModel builtIn)
        {
            builtIn.Find(slice, hits);
            if (hits.Count == 0) return;
            piece = region.Text.Substring(start, length);
        }
        else
        {
            piece = region.Text.Substring(start, length);
            hits.AddRange(model.Find(piece));
        }
        if (hits.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
        foreach (var hit in hits)
        {
            if (hit.Start < 0 || hit.Length <= 0 || hit.Start > length - hit.Length || !PrivacyPolicy.EntityTypes.Contains(hit.Type))
                throw new InvalidOperationException("invalid-span");
        }
        LogMasking.RemoveInstrumentNameSpans(piece, hits, policy.DisplayFieldExceptions);
        LogPersonContext.RemoveTechnicalSpans(piece, 0, piece.Length, hits);
        TransliteratedPersonNames.PreserveTechnicalLogins(piece, hits);
        LogSensitiveFields.PreserveTraceIds(piece, hits);
        foreach (var hit in hits)
        {
            int srcStart = region.SourceOffset(start + hit.Start);
            int srcEnd = region.SourceOffset(start + hit.Start + hit.Length);
            int escapeLayers = srcEnd - srcStart == hit.Length ? 0 : region.Layers;
            learned.Add(hit with { Start = srcStart, Length = srcEnd - srcStart, JsonEscapeLayers = escapeLayers });
            if (learned.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
        }
    }

    /// <summary>Mask only known query values and end the span before URL and JSON delimiters.</summary>
    private void ProjectQueries(NestedJsonMessagePersonNames.MappedText query, int start, int length, List<EntitySpan> spans)
    {
        ReadOnlySpan<char> part = query.Text.AsSpan(start, length);
        if (part.IndexOfAny('?', '&') < 0) return;
        string normalized = NormalizeQueryDelimiters(part, out int[] decodedMap);
        foreach (Match match in RoutedParameters.Matches(normalized))
        {
            string name = DecodeParameter(match.Groups["name"].Value);
            string? type = policy.FieldType(name);
            Group value = match.Groups["value"];
            if (type is null || value.Length == 0) continue;
            int decodedStart = start + decodedMap[value.Index];
            int decodedEnd = start + decodedMap[value.Index + value.Length];
            int srcStart = query.SourceOffset(decodedStart);
            int srcEnd = query.SourceOffset(decodedEnd);
            ReadOnlySpan<char> rawValue = query.Text.AsSpan(decodedStart, decodedEnd - decodedStart);
            bool url = rawValue.IndexOfAny('%', '+') >= 0;
            bool escaped = srcEnd - srcStart != rawValue.Length;
            spans.Add(new EntitySpan(srcStart, srcEnd - srcStart, type, 300, url)
            {
                JsonEscapeLayers = escaped ? query.Layers : 0
            });
            if (spans.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
        }
    }

    /// <summary>Leave URL assignments to the query scanner, which also recognizes escaped ampersands.</summary>
    private static bool IsQueryName(string text, int start)
    {
        if (start == 0) return false;
        return text[start - 1] is '?' or '&'
            || (start >= 6 && text.AsSpan(start - 6, 6).Equals("\\u0026", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Treat a literal JSON unicode ampersand as a query delimiter without shifting later source offsets.</summary>
    private static string NormalizeQueryDelimiters(ReadOnlySpan<char> text, out int[] map)
    {
        var output = new StringBuilder(text.Length);
        var positions = new List<int>(text.Length + 1);
        for (int i = 0; i < text.Length;)
        {
            if (i + 6 <= text.Length && text.Slice(i, 6).Equals("\\u0026", StringComparison.OrdinalIgnoreCase))
            {
                positions.Add(i);
                output.Append('&');
                i += 6;
            }
            else
            {
                positions.Add(i);
                output.Append(text[i]);
                i++;
            }
        }
        positions.Add(text.Length);
        map = positions.ToArray();
        return output.ToString();
    }

    /// <summary>JSON-decode a query value, decode percent or plus whitespace, then restore both encodings.</summary>
    private string ReplaceEscapedQuery(string raw, int layers, string type)
    {
        string decoded = raw;
        int applied = 0;
        for (int i = 0; i < layers && applied < 8; i++)
        {
            if (!JsonMessagePersonNames.TryDecode(decoded, out string next) || next == decoded) break;
            decoded = next;
            applied++;
        }
        decoded = DecodeParameter(decoded);
        string replacement = Uri.EscapeDataString(aliases.ReplaceWithShape(type, decoded));
        var encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;
        for (int i = 0; i < applied; i++)
            replacement = JsonEncodedText.Encode(replacement, encoder).ToString();
        return replacement;
    }

    private static bool HasWord(ReadOnlySpan<char> text)
    {
        foreach (char c in text)
            if (char.IsLetterOrDigit(c)) return true;
        return false;
    }
}
