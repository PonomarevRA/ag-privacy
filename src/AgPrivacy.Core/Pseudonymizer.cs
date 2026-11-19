using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace AgPrivacy;

/// <summary>Детерминированные domain-separated aliases; ключ предоставляется доверенным host и удаляется при Dispose.</summary>
public sealed class Pseudonymizer : IDisposable
{
    private const string MarkerPrefix = "[REDACTED:v1:";
    private readonly byte[] key;
    private readonly string scope;
    private bool disposed;
    private readonly object sync = new();

    /// <summary>Принимает случайный ключ не короче32байт; scope задаёт рабочее пространство/сервис/задачу.</summary>
    public Pseudonymizer(ReadOnlySpan<byte> key, string scope)
    {
        if (key.Length < 32 || key.Length > 128 || string.IsNullOrWhiteSpace(scope) || scope.Length > 128)
            throw new ArgumentException("invalid-key-or-scope");
        this.key = key.ToArray();
        this.scope = scope;
    }

    /// <summary>Создаёт явно маркированный HMAC-SHA256; не раскрывает длину, начало или конец оригинала.</summary>
    public string Replace(string type, string value)
    {
        lock (sync) return ReplaceCore(type, value);
    }

    /// <summary>Add a display rule code without changing how the original value is hashed.</summary>
    internal string ReplaceForDisplay(string type, string value, string rule)
    {
        string marker = Replace(type, value);
        return $"{MarkerPrefix}{rule}:{marker[MarkerPrefix.Length..]}";
    }

    /// <summary>Generate a shape-preserving display substitute with its own HMAC domain.</summary>
    internal string ReplaceWithShape(string type, string value)
    {
        byte[] seed;
        lock (sync) seed = ComputeDigest("ag-privacy-display-shape-v1", type, value);
        try { return DisplayValueSubstitution.Replace(value, seed, type == "GUID"); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }

    /// <summary>Identify a stream replacement in a separate HMAC domain with exact input semantics.</summary>
    internal string StreamJournalId(string type, string value)
    {
        byte[] digest;
        lock (sync) digest = ComputeDigest("ag-privacy-stream-journal-v1", type, value);
        try { return Convert.ToHexStringLower(digest); }
        finally { CryptographicOperations.ZeroMemory(digest); }
    }

    /// <summary>Весь MAC вычисляется под тем же lock, что и обнуление ключа.</summary>
    private string ReplaceCore(string type, string value)
    {
        string canonical = value;
        if (type == "GUID" && Guid.TryParse(value, out Guid guid)) canonical = guid.ToString("D");
        // Секреты сохраняют точные codepoints; PERSON не пытается отождествлять склонения или разных людей.
        if (type == "PERSON") canonical = value.Normalize(NormalizationForm.FormC).Trim().ToUpperInvariant();
        byte[] digest = ComputeDigest("ag-privacy-hmac-v1", type, canonical);
        return $"{MarkerPrefix}{Convert.ToHexStringLower(digest)}]";
    }

    /// <summary>Derive a digest with the selected purpose and the host's scope while holding the key lock.</summary>
    private byte[] ComputeDigest(string purpose, string type, string value)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (!PrivacyPolicy.EntityTypes.Contains(type)) throw new ArgumentException("invalid-entity-type");
        using var input = new MemoryStream();
        Span<byte> size = stackalloc byte[4];
        foreach (string part in new[] { purpose, scope, type, value })
        {
            byte[] bytes = Encoding.UTF8.GetBytes(part);
            BinaryPrimitives.WriteInt32BigEndian(size, bytes.Length);
            input.Write(size); input.Write(bytes);
            CryptographicOperations.ZeroMemory(bytes);
        }
        byte[] digest = HMACSHA256.HashData(key, input.GetBuffer().AsSpan(0, (int)input.Length));
        CryptographicOperations.ZeroMemory(input.GetBuffer().AsSpan(0, (int)input.Length));
        return digest;
    }

    /// <summary>Обнуляет собственную копию ключа. Не обещает стирание строк и чужих копий в памяти.</summary>
    public void Dispose() { lock (sync) { if (disposed) return; CryptographicOperations.ZeroMemory(key); disposed = true; } }
}
