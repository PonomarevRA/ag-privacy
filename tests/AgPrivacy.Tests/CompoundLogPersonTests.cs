using System.Text;
using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class CompoundLogPersonTests
{
    /// <summary>Substitute the whole personal value, with the same punctuation, in a validated stream record.</summary>
    [Theory]
    [InlineData("ФИО: ", "алёна Зорничева‐Полуянцева")]
    [InlineData("контакт: ", "Р. А. Левчанов‑Бурцевич")]
    [InlineData("recipient: ", "Dorevko-Valedzin A.M.")]
    [InlineData("service client: sync-worker. ФИО: ", "Зорничева‐Полуянцева Р. А.")]
    public async Task MasksCompoundNamesAndInitials(string label, string name)
    {
        using var aliases = new Pseudonymizer(new byte[32], "compound-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        const string trace = "fixture-7";
        string source = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["trace.id"] = trace,
            ["message"] = label + name + "; результат принят"
        });
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(source + "\n"));
        using var output = new MemoryStream();
        var stream = new StreamingPrivacyMasker(policy, aliases);
        var result = await stream.MaskAsync(input, output);
        Assert.Equal(0, result.ConservativeMasks);

        using var doc = JsonDocument.Parse(output.ToArray());
        Assert.Equal(trace, doc.RootElement.GetProperty("trace.id").GetString());
        string value = doc.RootElement.GetProperty("message").GetString()!;
        Assert.StartsWith(label, value);
        Assert.EndsWith("; результат принят", value);
        string replacement = value[label.Length..^"; результат принят".Length];
        Assert.Equal(name.Length, replacement.Length);
        for (int i = 0; i < name.Length; i++)
        {
            if (char.IsLetter(name[i])) Assert.True(replacement[i] != name[i]);
            else Assert.Equal(name[i], replacement[i]);
        }
    }

    /// <summary>Keep compounds and initials when their nearest assignment describes a technical value.</summary>
    [Theory]
    [InlineData("service client: Dorevko-Valedzin A.M.")]
    [InlineData("request.contact: Maria Dorevko-Valedzin")]
    [InlineData("report name: Контур А.Б.")]
    public async Task PreservesTechnicalSpelling(string message)
    {
        using var aliases = new Pseudonymizer(new byte[32], "compound-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        string source = JsonSerializer.Serialize(new { message }) + "\n";
        using var input = new MemoryStream(Encoding.UTF8.GetBytes(source));
        using var output = new MemoryStream();
        var stream = new StreamingPrivacyMasker(policy, aliases);
        await stream.MaskAsync(input, output);
        Assert.True(source == Encoding.UTF8.GetString(output.ToArray()));
    }
}
