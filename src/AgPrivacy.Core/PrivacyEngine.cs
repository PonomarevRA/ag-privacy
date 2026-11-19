using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgPrivacy;

/// <summary>Fail-closed граница выдачи: strict скрывает неизвестные значения, модель используется только в явно heuristic режиме.</summary>
public sealed class PrivacyEngine(PrivacyPolicy policy, Pseudonymizer aliases, IPersonDetector? persons = null, TaskDisclosure? disclosure = null)
{
    private readonly TextRedactor logRedactor = new(aliases, policy, persons);

    /// <summary>Trusted UI re-enable revokes any field exemption held by this engine.</summary>
    public void RevokeDisclosure() => disclosure?.Revoke();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>Очищает полную строку; strict гарантирует замену всей строки, а не полноту распознавания.</summary>
    public PrivacyResult SanitizeText(string input, bool heuristic = false)
    {
        long started = PrivacyMetrics.Start();
        PrivacyResult? result = null;
        try
        {
            ValidateSize(input);
            if (!heuristic) return result = Result(aliases.Replace("TEXT", input), null, 1, true);
            var text = new TextRedactor(aliases, policy, persons).Redact(input);
            return result = Result(text.Text, null, text.Count, false);
        }
        catch (Exception e) when (Recoverable(e)) { return result = Blocked(); }
        finally { PrivacyMetrics.Record(started, heuristic ? "heuristic_text" : "strict_text", result); }
    }

    /// <summary>Pseudonymize GUID tokens in log text, keeping the surrounding text and MasterId values for display.</summary>
    public PrivacyResult SanitizeGuidsForDisplay(string input)
    {
        long started = PrivacyMetrics.Start();
        PrivacyResult? result = null;
        try
        {
            ValidateSize(input);
            var masked = logRedactor.RedactGuids(input);
            return result = new(true, false, "guid-only-redaction-for-display", masked.Text, null, masked.Count,
                policy.Version, persons?.Version ?? "none", [], null);
        }
        catch (Exception e) when (Recoverable(e)) { return result = Blocked(); }
        finally { PrivacyMetrics.Record(started, "guid_only", result); }
    }

    /// <summary>Mask detected types in log text for display and return counts of the markers emitted.</summary>
    public PrivacyResult SanitizeTypedLogForDisplay(string input) => SanitizeTypedLogForDisplay(input, includePreview: false);

    /// <summary>Include replacement offsets in the output text when requested.</summary>
    public PrivacyResult SanitizeTypedLogForDisplay(string input, bool includePreview)
    {
        long started = PrivacyMetrics.Start();
        PrivacyResult? result = null;
        try
        {
            ValidateSize(input);
            var replacementsByType = new Dictionary<string, int>(StringComparer.Ordinal);
            List<MaskHighlight>? highlights = includePreview ? [] : null;
            var masked = logRedactor.RedactTypedLog(input, replacementsByType, highlights);
            return result = new(true, false, "typed-log-redaction-for-display", masked.Text, null, masked.Count,
                policy.Version, persons?.Version ?? "none", [], null)
            {
                ReplacementsByType = replacementsByType,
                Preview = highlights is null ? null : new(masked.Text, highlights)
            };
        }
        catch (Exception e) when (Recoverable(e)) { return result = Blocked(); }
        finally { PrivacyMetrics.Record(started, "log_types", result); }
    }

    /// <summary>Очищает и ключи, и листья JSON до индексирования/пагинации; ошибки не содержат rejected input.</summary>
    public PrivacyResult SanitizeJson(string json, PrivacyContext? context = null) =>
        MeasureJson(json, context, preserveFieldNames: false);

    /// <summary>Mask sensitive data while retaining ordinary JSON values and field names for local display.</summary>
    public PrivacyResult SanitizeJsonForDisplay(string json) =>
        SanitizeJsonForDisplay(json, policy.DisplayFieldExceptions);

    /// <summary>Apply an explicit list to this display request only.</summary>
    public PrivacyResult SanitizeJsonForDisplay(string json, DisplayFieldExceptions exceptions) =>
        MeasureJson(json, null, preserveFieldNames: true, exceptions);

    /// <summary>Include the JSON preview and its replacement offsets when requested.</summary>
    public PrivacyResult SanitizeJsonForDisplay(string json, DisplayFieldExceptions exceptions, bool includePreview) =>
        MeasureJson(json, null, preserveFieldNames: true, exceptions, includePreview);

    /// <summary>Record one operation for either public JSON entry point.</summary>
    private PrivacyResult MeasureJson(string json, PrivacyContext? context, bool preserveFieldNames, DisplayFieldExceptions? exceptions = null, bool includePreview = false)
    {
        long started = PrivacyMetrics.Start();
        PrivacyResult? result = null;
        try { return result = SanitizeJsonCore(json, context, preserveFieldNames, exceptions, includePreview); }
        finally { PrivacyMetrics.Record(started, preserveFieldNames ? "strict_display" : "strict_json", result); }
    }

    /// <summary>Mask a verified module's inner JSON call. Its outer boundary records the final result.</summary>
    internal PrivacyResult SanitizeVerifiedJson(string json) =>
        SanitizeJsonCore(json, null, preserveFieldNames: false);

    /// <summary>Walk one bounded JSON document with the requested key policy.</summary>
    private PrivacyResult SanitizeJsonCore(string json, PrivacyContext? context, bool preserveFieldNames, DisplayFieldExceptions? exceptions = null, bool includePreview = false)
    {
        try
        {
            ValidateSize(json);
            JsonNode? root = JsonNode.Parse(json, new JsonNodeOptions { PropertyNameCaseInsensitive = false }, new JsonDocumentOptions { MaxDepth = PrivacyLimits.Depth });
            var state = new WalkState
            {
                PreserveFieldNames = preserveFieldNames,
                Preview = includePreview ? new() : null,
                ReplacementsByType = preserveFieldNames ? new(StringComparer.Ordinal) : null,
                Exceptions = exceptions ?? policy.DisplayFieldExceptions,
                CanDisclose = !preserveFieldNames && disclosure?.Matches(context, policy.Version, DisclosureDocument.Json(json)) == true
            };
            JsonNode? cleaned = Walk(root, null, state, 0, allowPublic: !preserveFieldNames, allowDisplayFallback: preserveFieldNames);
            if (preserveFieldNames)
                return new(true, false, "strict-redaction-for-display", null, cleaned, state.Replacements,
                    policy.Version, persons?.Version ?? "none", [], null) { ReplacementsByType = state.ReplacementsByType, Preview = state.Preview?.Build(cleaned) };

            return Result(null, cleaned, state.Replacements, true, state.Disclosed);
        }
        catch (Exception e) when (Recoverable(e)) { return Blocked(); }
    }

    /// <summary>Заголовок задаёт тип всего столбца; untrusted table не может включить public value exceptions.</summary>
    public PrivacyResult SanitizeTable(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string?>> rows, PrivacyContext? context = null)
    {
        long started = PrivacyMetrics.Start();
        PrivacyResult? result = null;
        try
        {
            if (headers.Count is 0 or > 128 || rows.Count > 2048) return result = Blocked();
            int totalBytes = 0;
            foreach (string header in headers) totalBytes = checked(totalBytes + StrictUtf8.GetByteCount(header));
            foreach (var row in rows)
            {
                if (row.Count != headers.Count) return result = Blocked();
                foreach (string? cell in row) totalBytes = checked(totalBytes + StrictUtf8.GetByteCount(cell ?? ""));
            }
            if (totalBytes > PrivacyLimits.InputBytes) return result = Blocked();
            var state = new WalkState { CanDisclose = disclosure?.Matches(context, policy.Version, DisclosureDocument.Table(headers,rows)) == true }; var cleanedRows = new JsonArray();
            foreach (var row in rows)
            {
                if (row.Count != headers.Count) return result = Blocked();
                var cleaned = new JsonArray();
                for (int i = 0; i < row.Count; i++)
                {
                    ValidateSize(headers[i]); ValidateSize(row[i] ?? "");
                    // Header text is not proof of a public technical value.
                    cleaned.Add(Walk(row[i] is null ? null : JsonValue.Create(row[i]), headers[i], state, 0, false));
                }
                cleanedRows.Add((JsonNode)cleaned);
            }
            var safeHeaders = new JsonArray();
            foreach (string header in headers)
            {
                bool known = policy.IsKnownField(header);
                safeHeaders.Add((JsonNode?)JsonValue.Create(known ? PrivacyPolicy.NormalizeField(header) : aliases.Replace("KEY", header)));
                if (!known) state.Replacements++;
            }
            return result = Result(null, new JsonObject { ["headers"] = safeHeaders, ["rows"] = cleanedRows }, state.Replacements, true, state.Disclosed);
        }
        catch (Exception e) when (Recoverable(e)) { return result = Blocked(); }
        finally { PrivacyMetrics.Record(started, "strict_table", result); }
    }

    /// <summary>Рекурсивная обработка ограничена глубиной и числом узлов, без сохранения raw mapping.</summary>
    private JsonNode? Walk(JsonNode? node, string? field, WalkState state, int depth, bool allowPublic, bool allowDisplayFallback = false, LogField logField = LogField.None)
    {
        if (++state.Nodes > PrivacyLimits.Nodes || depth > PrivacyLimits.Depth) throw new InvalidOperationException("document-limit");
        if (node is null) return null;
        if (allowDisplayFallback && field is not null && HasDisplayFieldRule(field)) allowDisplayFallback = false;
        if (node is JsonObject obj)
        {
            var result = new JsonObject();
            foreach (var pair in obj)
            {
                string key = MaskJsonKey(pair.Key, state);
                if (key != pair.Key) state.Preview?.RecordKey(result, key);
                result.Add(key, Walk(pair.Value, pair.Key, state, depth + 1, allowPublic, allowDisplayFallback, state.PreserveFieldNames ? LogMasking.FieldFor(logField, pair.Key) : LogField.None));
            }
            return result;
        }
        if (node is JsonArray array)
        {
            var result = new JsonArray();
            foreach (var item in array) result.Add(Walk(item, field, state, depth + 1, allowPublic, allowDisplayFallback, logField));
            return result;
        }
        JsonElement element = JsonSerializer.SerializeToElement(node, PrivacyJsonContext.Default.JsonNode);
        if (allowDisplayFallback && DisplayValueFormats.IsOrdinaryPrimitive(element.ValueKind)) return node.DeepClone();
        string value = element.ValueKind == JsonValueKind.String ? element.GetString()! : element.GetRawText();
        if (allowDisplayFallback && element.ValueKind == JsonValueKind.String)
        {
            if (logField == LogField.Message)
            {
                List<MaskHighlight>? fragments = state.Preview is null ? null : [];
                var maskedLog = logRedactor.RedactLogMessage(value, state.Exceptions, state.ReplacementsByType, fragments);
                state.Replacements += maskedLog.Count;
                return MaskPreviewBuilder.Value(maskedLog.Text, state.Preview, fragments);
            }
            if (logField == LogField.TraceId)
            {
                state.Record("TRACE_ID");
                return MaskPreviewBuilder.Value(LogMasking.TraceId(aliases, value), state.Preview);
            }
        }
        if (allowPublic && field is not null && policy.IsApprovedPublicValue(field, value)) return node.DeepClone();
        string type = field is null ? "TEXT" : policy.FieldType(field) ?? "TEXT";
        if (state.CanDisclose && field is not null && disclosure?.Permits(field, value, type) == true)
        {
            state.Disclosed.Add(DisclosureAuthority.CanonicalField(field));
            return node.DeepClone();
        }
        if (type == "TEXT" && element.ValueKind == JsonValueKind.Number) type = "NUMBER";
        if (type == "TEXT" && element.ValueKind is JsonValueKind.True or JsonValueKind.False) type = "BOOLEAN";
        string? displayRule = state.PreserveFieldNames ? DisplayRule(field, type, value, allowDisplayFallback, state.Exceptions) : null;
        if (state.PreserveFieldNames && displayRule is null) return node.DeepClone();

        state.Record(displayRule);
        string masked = displayRule is null
            ? aliases.Replace(type, value)
            : aliases.ReplaceForDisplay(type, value, displayRule);
        return MaskPreviewBuilder.Value(masked, state.Preview);
    }

    /// <summary>Infer a display rule from a string only if its field does not already define one.</summary>
    private string? DisplayRule(string? field, string type, string value, bool allowDisplayFallback, DisplayFieldExceptions exceptions)
    {
        string rule = DisplayMaskRules.ForField(field, type);
        if (rule != "TEXT" || !allowDisplayFallback) return rule;
        bool skipPersonDetection = exceptions.Contains(field) && LogMasking.CanSkipPersonDetection(field, value);
        return DisplayValueFormats.RuleForText(value, policy, skipPersonDetection ? null : persons);
    }

    /// <summary>Check explicit field rules before applying display fallback behavior.</summary>
    private bool HasDisplayFieldRule(string field) => policy.IsKnownField(field) || SoftPartMasker.HasFieldRule(field);

    /// <summary>Apply the configured JSON key policy and count any pseudonymized key.</summary>
    private string MaskJsonKey(string key, WalkState state)
    {
        if (state.PreserveFieldNames)
        {
            string? rule = JsonFieldNames.ContactRule(key);
            if (rule is null) return key;
            state.Record(rule);
            return aliases.ReplaceForDisplay("KEY", key, rule);
        }
        else if (policy.IsKnownField(key))
        {
            return PrivacyPolicy.NormalizeField(key);
        }

        state.Replacements++;
        return aliases.Replace("KEY", key);
    }

    private PrivacyResult Result(string? text, JsonNode? data, int count, bool safe, HashSet<string>? disclosed = null)
    {
        if (disclosed?.Count > 0 && disclosure?.IsCurrent != true) return Blocked();
        string status = safe ? "strict-redaction" : "heuristic-not-security-qualified";
        if (disclosed?.Count > 0) status = "strict-with-human-approved-task-disclosure";
        return new(true, safe, status, text, data, count, policy.Version, persons?.Version ?? "none",
            disclosed?.Order(StringComparer.Ordinal).ToArray() ?? [], disclosed?.Count > 0 ? disclosure?.ReceiptId : null);
    }
    private PrivacyResult Blocked() => new(false, false, "privacy-processing-blocked", null, null, 0, policy.Version, persons?.Version ?? "none", [], null);
    private static bool Recoverable(Exception e) => e is ArgumentException or InvalidOperationException or JsonException or OverflowException or System.Text.RegularExpressions.RegexMatchTimeoutException;
    private static void ValidateSize(string input) { if (StrictUtf8.GetByteCount(input) > PrivacyLimits.InputBytes) throw new ArgumentException("input-limit"); }
    private sealed class WalkState
    {
        public int Nodes;
        public int Replacements;
        public bool CanDisclose;
        public bool PreserveFieldNames;
        public DisplayFieldExceptions Exceptions = DisplayFieldExceptions.Default;
        public HashSet<string> Disclosed = new(StringComparer.Ordinal);
        public Dictionary<string, int>? ReplacementsByType;
        public MaskPreviewBuilder? Preview;

        /// <summary>Record a replacement and its display rule when collecting display statistics.</summary>
        public void Record(string? rule)
        {
            Replacements++;
            if (rule is not null && ReplacementsByType is not null)
                ReplacementsByType[rule] = ReplacementsByType.GetValueOrDefault(rule) + 1;
        }
    }
}
