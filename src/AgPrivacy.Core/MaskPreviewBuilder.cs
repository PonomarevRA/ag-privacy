using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgPrivacy;

/// <summary>Keep replacement locations while building a display-only JSON preview.</summary>
internal sealed class MaskPreviewBuilder
{
    private readonly Dictionary<JsonNode, IReadOnlyList<MaskHighlight>?> maskedValues = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<JsonObject, HashSet<string>> maskedKeys = new(ReferenceEqualityComparer.Instance);
    private readonly StringBuilder text = new();
    private readonly List<MaskHighlight> highlights = new();

    /// <summary>Record the resulting key only when its masking rule changed it.</summary>
    internal void RecordKey(JsonObject owner, string key)
    {
        if (!maskedKeys.TryGetValue(owner, out var keys))
        {
            keys = new(StringComparer.Ordinal);
            maskedKeys.Add(owner, keys);
        }
        keys.Add(key);
    }

    /// <summary>Create a JSON string and optionally record the entire value or its replaced fragments.</summary>
    internal static JsonValue Value(string value, MaskPreviewBuilder? preview, IReadOnlyList<MaskHighlight>? fragments = null)
    {
        var node = JsonValue.Create(value);
        if (preview is not null && (fragments is null || fragments.Count > 0))
            preview.maskedValues.Add(node, fragments);
        return node;
    }

    /// <summary>Format the masked JSON and translate recorded replacements to UTF-16 offsets.</summary>
    internal MaskPreview Build(JsonNode? root)
    {
        WriteNode(root, 0);
        return new(text.ToString(), highlights);
    }

    /// <summary>Walk the output in document order, keeping the original precision of numeric tokens.</summary>
    private void WriteNode(JsonNode? node, int depth)
    {
        switch (node)
        {
            case JsonObject obj:
                text.Append('{');
                maskedKeys.TryGetValue(obj, out var keys);
                bool first = true;
                foreach (var (key, value) in obj)
                {
                    BeginItem(first, depth);
                    WriteString(key, keys?.Contains(key) == true);
                    text.Append(": ");
                    WriteNode(value, depth + 1);
                    first = false;
                }
                if (!first) Indent(depth);
                text.Append('}');
                break;

            case JsonArray array:
                text.Append('[');
                for (int i = 0; i < array.Count; i++)
                {
                    BeginItem(i == 0, depth);
                    WriteNode(array[i], depth + 1);
                }
                if (array.Count > 0) Indent(depth);
                text.Append(']');
                break;

            case JsonValue value when value.TryGetValue<string>(out var str):
                bool masked = maskedValues.TryGetValue(value, out var fragments);
                WriteString(str, masked, fragments);
                break;

            default:
                text.Append(node?.ToJsonString() ?? "null");
                break;
        }
    }

    /// <summary>Quote a JSON string and mark only replacements after JSON escaping.</summary>
    private void WriteString(string value, bool masked, IReadOnlyList<MaskHighlight>? fragments = null)
    {
        text.Append('"');
        if (fragments is null)
            AppendEncoded(value, masked);
        else
        {
            int offset = 0;
            foreach (var fragment in fragments)
            {
                AppendEncoded(value.AsSpan(offset, fragment.Start - offset), false);
                AppendEncoded(value.AsSpan(fragment.Start, fragment.Length), true);
                offset = fragment.Start + fragment.Length;
            }
            AppendEncoded(value.AsSpan(offset), false);
        }
        text.Append('"');
    }

    /// <summary>Append one escaped piece and track its encoded extent.</summary>
    private void AppendEncoded(ReadOnlySpan<char> value, bool masked)
    {
        if (value.IsEmpty) return;
        int start = text.Length;
        text.Append(JsonEncodedText.Encode(value, JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString());
        if (masked) highlights.Add(new(start, text.Length - start));
    }

    private void BeginItem(bool first, int depth)
    {
        if (!first) text.Append(',');
        Indent(depth + 1);
    }

    private void Indent(int depth) => text.Append('\n').Append(' ', depth * 2);
}
