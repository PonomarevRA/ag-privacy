using System.Security.Cryptography;
using System.Text;
namespace AgPrivacy.Testing;
/// <summary>Test-only fixture replay. Exclude this assembly from products. A manifest is an author assertion of synthetic provenance, never a PII detector.</summary>
public sealed class SyntheticFixtureProfile
{
    private readonly HashSet<string> hashes;
    public SyntheticFixtureProfile(IEnumerable<string> approvedFixtureSha256)
    {
        hashes=new(StringComparer.Ordinal);
        foreach(string hash in approvedFixtureSha256)
            if(hashes.Count>=256 || hash.Length!=64 || hash.Any(c=>!char.IsAsciiHexDigit(c)) || !hashes.Add(hash.ToLowerInvariant())) throw new ArgumentException("invalid-synthetic-manifest");
    }
    /// <summary>Returns unchanged bytes only for exact explicitly approved synthetic fixtures; never infers test mode from input flags.</summary>
    public string Replay(string fixture)
    {
        if(new UTF8Encoding(false,true).GetByteCount(fixture)>262144)throw new InvalidOperationException("fixture-limit");
        string hash=Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(fixture)));
        if(!hashes.Contains(hash))throw new InvalidOperationException("fixture-not-approved");
        return fixture;
    }
}
