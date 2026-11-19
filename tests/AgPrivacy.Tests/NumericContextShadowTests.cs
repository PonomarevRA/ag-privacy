using System.Text;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class NumericContextShadowTests
{
    /// <summary>Disambiguate equal values by role and leave streamed JSON and journal bytes unchanged.</summary>
    [Fact]
    public async Task CountsNumericDecisionsWithoutChangingMasking()
    {
        string row = """{"trace.id":"3a0e1ab96f8c400caf6a0000000000","otp":"000042","message":"\u043a\u043f\u043f=990030001; operationId=990030001; customer id=990030001; request id=990030001 or tax id; title=Роман; email=fixture@example.invalid"}""";
        string inputText = string.Concat(Enumerable.Repeat(row + "\n", 50));
        using var aliases = new Pseudonymizer(new byte[32], "numeric-context-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var model = NumericContextShadow.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "numeric-context-shadow.bin")));

        var baseline = await Run(new StreamingPrivacyMasker(policy, aliases));
        var shadow = await Run(new StreamingPrivacyMasker(policy, aliases, null, null, model));

        Assert.Equal(baseline.Output, shadow.Output);
        Assert.Equal(baseline.Journal, shadow.Journal);
        Assert.Equal(baseline.Result.Replacements, shadow.Result.Replacements);
        Assert.Null(baseline.Result.NumericContext);
        Assert.Equal(new NumericContextCounts(200, 0, 50, 50, 50, 50), shadow.Result.NumericContext);

        /// <summary>Execute identical UTF-8 input with a fresh stream and journal.</summary>
        async Task<(byte[] Output, string Journal, StreamMaskResult Result)> Run(StreamingPrivacyMasker pipe)
        {
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(inputText));
            using var output = new MemoryStream();
            using var journal = new StringWriter();
            var result = await pipe.MaskAsync(input, output, journal);
            return (output.ToArray(), journal.ToString(), result);
        }
    }

    /// <summary>Count both roles in one clause and leave an explicitly denied role undecided.</summary>
    [Fact]
    public async Task ResolvesRolesIndependentlyAcrossValuesAndNegation()
    {
        const string row = """{"message":"id клиента 990030001, id запроса 990030002; request id is not 990030003"}""";
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(row));
        using var output = new MemoryStream();
        using var aliases = new Pseudonymizer(new byte[32], "numeric-role-context-test");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var model = NumericContextShadow.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "numeric-context-shadow.bin")));
        var pipe = new StreamingPrivacyMasker(policy, aliases, null, null, model);

        var result = await pipe.MaskAsync(input, output);

        Assert.Equal(new NumericContextCounts(3, 0, 0, 1, 1, 1), result.NumericContext);
    }

    /// <summary>Only unknown candidates reach the fallback and explicit conflict never becomes a proposal.</summary>
    [Fact]
    public async Task PersonalIdFallbackCountsObservationsWithoutChangingTheStream()
    {
        const string row = """{"message":"employee badge 990030001; operationId=990030002; user identifier 990030003 or operation id"}""";
        var weights = new byte[PersonalIdShadow.ModelBytes];
        "APPID001"u8.CopyTo(weights);
        // Zero weights and threshold make every eligible candidate a proposal.
        var fallback = PersonalIdShadow.Load(weights);
        var numeric = NumericContextShadow.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "numeric-context-shadow.bin")));
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        using var aliases = new Pseudonymizer(new byte[32], "personal-id-shadow-test");

        var baseline = await Run(numeric);
        var shadow = await Run(numeric.WithPersonalIdShadow(fallback));

        Assert.Equal(baseline.Text, shadow.Text);
        Assert.Equal(baseline.Result.NumericContext, shadow.Result.NumericContext);
        Assert.Null(baseline.Result.PersonalIdContext);
        Assert.Equal(new PersonalIdShadowCounts(2, 1), shadow.Result.PersonalIdContext);

        /// <summary>Run each comparison with its own input and output streams.</summary>
        async Task<(byte[] Text, StreamMaskResult Result)> Run(NumericContextShadow observer)
        {
            using var input = new MemoryStream(Encoding.UTF8.GetBytes(row));
            using var output = new MemoryStream();
            var pipe = new StreamingPrivacyMasker(policy, aliases, null, null, observer);
            var result = await pipe.MaskAsync(input, output);
            return (output.ToArray(), result);
        }
    }

    /// <summary>Both model versions load, and the updated format distinguishes a nearby object from a person.</summary>
    [Fact]
    public async Task PersonalIdModelVersionsAndContextAreIndependent()
    {
        const string person = "Unique user ID 990030001 recorded in the access log";
        const string action = "Code 990030001 identifies an action by the user";
        // A synthetic coefficient isolates the feature for the closer person role.
        var bytes = new byte[PersonalIdShadow.ModelBytes];
        System.Buffers.Binary.BinaryPrimitives.WriteSingleLittleEndian(bytes.AsSpan(8), 0.5f);
        System.Buffers.Binary.BinaryPrimitives.WriteSingleLittleEndian(bytes.AsSpan(12 + 12 * sizeof(float)), 1f);
        "APPID001"u8.CopyTo(bytes);
        var legacy = PersonalIdShadow.Load(bytes);
        "APPID002"u8.CopyTo(bytes);
        var current = PersonalIdShadow.Load(bytes);

        Assert.Equal(0, await Proposals(legacy, person));
        Assert.Equal(1, await Proposals(current, person));
        Assert.Equal(0, await Proposals(current, action));

        /// <summary>Validate the weights through the normal streaming observer.</summary>
        async Task<long> Proposals(PersonalIdShadow model, string message)
        {
            var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
            var numeric = NumericContextShadow.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "numeric-context-shadow.bin")));
            using var aliases = new Pseudonymizer(new byte[32], "personal-id-format-test");
            using var input = new MemoryStream(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new { message }));
            using var output = new MemoryStream();
            var pipe = new StreamingPrivacyMasker(policy, aliases, null, null, numeric.WithPersonalIdShadow(model));
            return (await pipe.MaskAsync(input, output)).PersonalIdContext!.Proposed;
        }
    }

    /// <summary>Reject weights with invalid format or nonfinite coefficients.</summary>
    [Fact]
    public void RejectsInvalidWeights()
    {
        byte[] weights = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "numeric-context-shadow.bin"));
        Assert.Throws<ArgumentException>(() => NumericContextShadow.Load(weights.AsSpan(0, weights.Length - 1)));
        System.Buffers.Binary.BinaryPrimitives.WriteSingleLittleEndian(weights.AsSpan(8), float.NaN);
        Assert.Throws<ArgumentException>(() => NumericContextShadow.Load(weights));
    }
}
