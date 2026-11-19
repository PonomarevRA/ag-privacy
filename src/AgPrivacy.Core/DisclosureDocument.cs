using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace AgPrivacy;
/// <summary>Exact captured unit binding: a changed/renamed table or JSON document requires a new human field approval.</summary>
public static class DisclosureDocument
{
    public static string Json(string json) => Convert.ToHexStringLower(SHA256.HashData(new UTF8Encoding(false,true).GetBytes(json)));
    /// <summary>Length-framed table digest distinguishes null, empty, column order and row boundaries.</summary>
    public static string Table(IReadOnlyList<string> headers, IReadOnlyList<IReadOnlyList<string?>> rows)
    {
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Add(hash,"ag-privacy-table-v1");Add(hash,headers.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach(string h in headers)Add(hash,h);
        foreach(var row in rows){Add(hash,"row");Add(hash,row.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));foreach(string? cell in row)Add(hash,cell);}
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
    private static void Add(IncrementalHash hash,string? value)
    {
        byte[] bytes=value is null ? [] : new UTF8Encoding(false,true).GetBytes(value);
        Span<byte> length=stackalloc byte[4];BinaryPrimitives.WriteInt32BigEndian(length,value is null ? -1 : bytes.Length);
        hash.AppendData(length);hash.AppendData(bytes);CryptographicOperations.ZeroMemory(bytes);
    }
}
