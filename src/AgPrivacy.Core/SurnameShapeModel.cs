using System.Buffers.Binary;

namespace AgPrivacy;

/// <summary>Score the spelling of a surname with a compact character model and no token lookup.</summary>
internal static class SurnameShapeModel
{
    private const int BucketCount = 1 << 14;

    /// <summary>Accept a candidate only at the caller's margin for the available context.</summary>
    internal static bool Predict(ReadOnlySpan<char> value, float margin)
    {
        if (value.Length is < 3 or > 40) return false;

        Span<char> word = stackalloc char[value.Length + 2];
        word[0] = '^';
        word[^1] = '$';
        for (int i = 0; i < value.Length; i++)
        {
            char lower = char.ToLowerInvariant(value[i]);
            char normalized = lower == 'ё' ? 'е' : lower;
            if (normalized is not (>= 'a' and <= 'z' or >= 'а' and <= 'я')) return false;
            word[i + 1] = normalized;
        }

        var weights = Model.Weights;
        float score = weights[0];
        for (int start = 0; start < word.Length - 1; start++)
        {
            uint hash = unchecked((2166136261u ^ word[start]) * 16777619u);
            for (int end = start + 1; end < Math.Min(start + 4, word.Length); end++)
            {
                hash = unchecked((hash ^ word[end]) * 16777619u);
                score += weights[1 + (hash & (BucketCount - 1))];
            }
        }
        return score >= margin;
    }

    private static class Model
    {
        internal static readonly float[] Weights = Load();

        /// <summary>Load the fixed-size weight vector once, independent of application model configuration.</summary>
        private static float[] Load()
        {
            using var source = typeof(SurnameShapeModel).Assembly.GetManifestResourceStream("AgPrivacy.surname-shape.bin")
                ?? throw new InvalidDataException("missing-surname-model");
            byte[] data = new byte[8 + 4 * BucketCount];
            source.ReadExactly(data);
            if (!data.AsSpan(0, 4).SequenceEqual("AGS1"u8) || source.ReadByte() != -1)
                throw new InvalidDataException("invalid-surname-model");

            float[] weights = new float[BucketCount + 1];
            for (int i = 0; i < weights.Length; i++)
                weights[i] = BinaryPrimitives.ReadSingleLittleEndian(data.AsSpan(4 + i * sizeof(float)));
            return weights;
        }
    }
}
