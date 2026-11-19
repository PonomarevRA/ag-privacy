using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AgPrivacy;

/// <summary>Trusted host issues this only after an actual human task-specific approval. The library cannot authenticate a human UI event.</summary>
public sealed class DisclosureAuthority : IDisposable
{
    private readonly byte[] key;
    private readonly TimeProvider clock;
    private bool disposed;
    private readonly object sync = new();
    public DisclosureAuthority(ReadOnlySpan<byte> approvalKey, TimeProvider? clock = null)
    {
        if (approvalKey.Length < 32 || approvalKey.Length > 128) throw new ArgumentException("invalid-approval-key");
        key = approvalKey.ToArray(); this.clock = clock ?? TimeProvider.System;
    }

    /// <summary>Not an agent tool: host attests explicit consent for a task, exact fields, purpose and at most1hour.</summary>
    public string IssueAfterHumanApproval(PrivacyContext context, IReadOnlyList<string> fields, string purpose, PrivacyPolicy policy, TimeSpan ttl, string documentDigest)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        PrivacyContextRules.Validate(context);
        if (documentDigest.Length != 64 || documentDigest.Any(c => !char.IsAsciiHexDigit(c))) throw new ArgumentException("invalid-document-binding");
        if (purpose.Length is 0 or > 256 || ttl <= TimeSpan.Zero || ttl > TimeSpan.FromHours(1) || fields.Count is 0 or > 32) throw new ArgumentException("invalid-disclosure-request");
        var names = new JsonArray(); var seen = new HashSet<string>();
        foreach (string field in fields)
        {
            string name = CanonicalField(field); string? type = policy.FieldType(name);
            // Initial release permits only rigid tax identifier fields. Secrets cannot be exempted by this grant type.
            if (type is not ("INN" or "KPP") || !seen.Add(name)) throw new ArgumentException("field-not-disclosable");
            names.Add((JsonNode?)JsonValue.Create(name));
        }
        var payload = new JsonObject { ["v"] = 1, ["product"] = context.ProductId, ["chat"] = context.ChatId, ["task"] = context.TaskId, ["fields"] = names, ["purpose"] = purpose,
            ["policy"] = policy.Version, ["document"] = documentDigest, ["expires"] = clock.GetUtcNow().Add(ttl).ToUnixTimeSeconds(), ["nonce"] = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)) };
        byte[] bytes = Encoding.UTF8.GetBytes(payload.ToJsonString());
        byte[] tag = Sign(bytes);
        return Convert.ToBase64String(bytes) + "." + Convert.ToBase64String(tag);
    }

    /// <summary>Validate a host attestation against current task/policy; untrusted flags or forged receipts cannot enable disclosure.</summary>
    public TaskDisclosure? Validate(string token, PrivacyContext context, PrivacyPolicy policy)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        PrivacyContextRules.Validate(context);
        try
        {
            if (token.Length > 8192) return null;
            string[] parts = token.Split('.'); if (parts.Length != 2) return null;
            byte[] bytes = Convert.FromBase64String(parts[0]); byte[] signature = Convert.FromBase64String(parts[1]);
            if (bytes.Length > 4096 || signature.Length != 32 || !CryptographicOperations.FixedTimeEquals(signature, Sign(bytes))) return null;
            using JsonDocument doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            var value = doc.RootElement;
            if (value.GetProperty("v").GetInt32() != 1 || value.GetProperty("product").GetString() != context.ProductId || value.GetProperty("chat").GetString() != context.ChatId || value.GetProperty("task").GetString() != context.TaskId || value.GetProperty("policy").GetString() != policy.Version) return null;
            long expires = value.GetProperty("expires").GetInt64(), now = clock.GetUtcNow().ToUnixTimeSeconds();
            if (expires <= now || expires > now + 3600) return null;
            var fields = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in value.GetProperty("fields").EnumerateArray())
            {
                string name = field.GetString()!;
                if (fields.Count >= 32 || name != CanonicalField(name) || policy.FieldType(name) is not ("INN" or "KPP") || !fields.Add(name)) return null;
            }
            if (fields.Count == 0) return null;
            return new TaskDisclosure(fields, context, policy.Version, value.GetProperty("document").GetString()!, expires, clock, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        }
        catch (Exception e) when (e is ArgumentException or FormatException or JsonException or InvalidOperationException or KeyNotFoundException) { return null; }
    }

    /// <summary>Known synonyms refer to the same explicitly requested field, not every identifier in a document.</summary>
    public static string CanonicalField(string name) => PrivacyPolicy.NormalizeField(name) switch { "инн" => "inn", "кпп" => "kpp", var field => field };
    private byte[] Sign(byte[] bytes)
    {
        lock (sync)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            byte[] prefix = Encoding.UTF8.GetBytes("ag-privacy-disclosure-v1\0");
            byte[] input = new byte[prefix.Length + bytes.Length];
            prefix.CopyTo(input, 0); bytes.CopyTo(input, prefix.Length);
            return HMACSHA256.HashData(key, input);
        }
    }
    public void Dispose() { lock (sync) { if (disposed) return; CryptographicOperations.ZeroMemory(key); disposed = true; } }
}

/// <summary>Only DisclosureAuthority can construct this task-bound checked capability. Do not expose receipt tokens to the agent.</summary>
public sealed class TaskDisclosure
{
    private readonly HashSet<string> fields;
    private readonly long expires;
    private readonly PrivacyContext context;
    private int revoked;
    private readonly string policyVersion;
    private readonly string documentDigest;
    private readonly long started;
    private readonly TimeSpan lifetime;
    private readonly TimeProvider clock;
    public string ReceiptId { get; }
    internal TaskDisclosure(HashSet<string> fields, PrivacyContext context, string policyVersion, string documentDigest, long expires, TimeProvider clock, string receiptId)
    {
        this.fields = fields; this.context = context; this.policyVersion = policyVersion; this.documentDigest = documentDigest;
        this.expires = expires; this.clock = clock; ReceiptId = receiptId;
        started = clock.GetTimestamp(); lifetime = TimeSpan.FromSeconds(expires - clock.GetUtcNow().ToUnixTimeSeconds());
    }
    public bool Matches(PrivacyContext? current, string policy, string document) => current == context && policy == policyVersion && document == documentDigest;
    /// <summary>Trusted host revokes this capability; re-enable must revoke both raw and field exceptions.</summary>
    public void Revoke() => Interlocked.Exchange(ref revoked, 1);
    public bool IsCurrent => Volatile.Read(ref revoked) == 0 && clock.GetUtcNow().ToUnixTimeSeconds() < expires && clock.GetElapsedTime(started) < lifetime;

    /// <summary>Approval disables only this tax-field rule; non-tax content in the same field is still hidden.</summary>
    public bool Permits(string field, string value, string? type)
    {
        if (!IsCurrent || !fields.Contains(DisclosureAuthority.CanonicalField(field))) return false;
        if (type == "INN") return value.Length is 10 or 12 && value.All(c => c is >= '0' and <= '9');
        if (type == "KPP") return value.Length == 9 && value.All(c => c is >= '0' and <= '9');
        return false;
    }
}
