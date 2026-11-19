using System.Text.Json.Serialization;
using System.Text.Json.Nodes;

namespace AgPrivacy;

/// <summary>Статическая JSON metadata обеспечивает NativeAOT без reflection-based сериализации.</summary>
[JsonSerializable(typeof(PrivacyResult))]
[JsonSerializable(typeof(JsonNode))]
[JsonSerializable(typeof(StreamReplacement))]
public partial class PrivacyJsonContext : JsonSerializerContext { }
