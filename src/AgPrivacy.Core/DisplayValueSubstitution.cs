using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace AgPrivacy;

/// <summary>Generate a display surrogate from a keyed seed, retaining separators and character classes.</summary>
internal static class DisplayValueSubstitution
{
    /// <summary>Replace letters and digits with different characters while keeping common UUID and log shapes.</summary>
    internal static string Replace(string value, ReadOnlySpan<byte> seed, bool hexadecimal)
    {
        // A full mask keeps encoded string values valid when replacing escape letters could break syntax.
        for (int i = 0; i + 1 < value.Length; i++)
            if (value[i] == '\\' && char.IsLetterOrDigit(value[i + 1])) return SoftPartFormats.FullMask;

        var output = new StringBuilder(value.Length);
        Span<byte> counter = stackalloc byte[4];
        Span<byte> block = stackalloc byte[32];
        int offset = block.Length;
        int blockIndex = 0;
        bool replaced = false;
        try
        {
            foreach (Rune rune in value.EnumerateRunes())
            {
                string? alphabet = AlphabetFor(rune, hexadecimal, output.Length == 0);
                if (alphabet is null)
                {
                    output.Append(rune.ToString());
                    continue;
                }

                if (offset == block.Length)
                {
                    BinaryPrimitives.WriteInt32BigEndian(counter, blockIndex++);
                    HMACSHA256.HashData(seed, counter, block);
                    offset = 0;
                }

                int original = rune.IsAscii || rune.Value <= char.MaxValue ? alphabet.IndexOf((char)rune.Value) : -1;
                int choice = original < 0
                    ? block[offset] % alphabet.Length
                    : (original + 1 + block[offset] % (alphabet.Length - 1)) % alphabet.Length;
                output.Append(alphabet[choice]);
                offset++;
                replaced = true;
            }
            return replaced ? output.ToString() : SoftPartFormats.FullMask;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }
    }

    /// <summary>Select an alphabet that keeps case, common scripts, and the hexadecimal UUID format.</summary>
    private static string? AlphabetFor(Rune rune, bool hexadecimal, bool first)
    {
        if (Rune.IsDigit(rune))
            return first && !hexadecimal && rune.Value is >= '1' and <= '9' ? "123456789" : "0123456789";
        if (!Rune.IsLetter(rune)) return null;

        if (hexadecimal && rune.Value is >= 'a' and <= 'f') return "abcdef";
        if (hexadecimal && rune.Value is >= 'A' and <= 'F') return "ABCDEF";
        if (rune.Value is >= 'а' and <= 'я' or 'ё') return "абвгдеёжзийклмнопрстуфхцчшщъыьэюя";
        if (rune.Value is >= 'А' and <= 'Я' or 'Ё') return "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
        return Rune.IsUpper(rune) ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "abcdefghijklmnopqrstuvwxyz";
    }
}
