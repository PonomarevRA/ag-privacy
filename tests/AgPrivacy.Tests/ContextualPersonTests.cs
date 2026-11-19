using System.Text.Json;
using Xunit;

namespace AgPrivacy.Tests;

public sealed class ContextualPersonTests
{
    /// <summary>Use the dictionary and role cues to mask the whole lowercase Russian name in all log views, including common Latin spellings.</summary>
    [Theory]
    [InlineData("заявка принята; получатель: «", "светлана соколова", "»; доставка готова")]
    [InlineData("запись обновлена; фио: «", "пётр берёзов алексеевич", "»; выполнено")]
    [InlineData("запись обновлена; фио: ", "пётр берёзов алексеевич", "; выполнено")]
    [InlineData("протокол принят; клиент: ", "иванов иван иванович", "; очередь")]
    [InlineData("протокол принят; контакт: ", "иван петрович рабинович", "; результат готов")]
    [InlineData("поручение передано; исполнитель ", "фёдор николаевич волков", " для проверки")]
    [InlineData("accepted; recipient: ", "yuliya ivanova", "; dispatch complete")]
    [InlineData("доставка; контакт: ", "iuliia ivanova", "; заявка закрыта")]
    [InlineData("transfer; full name: «", "Ivan Petrovich Petrov", "»; state ready")]
    [InlineData("transfer; fio: ", "petrov ivan petrovich", "; state ready")]
    [InlineData("отправка; исполнитель ", "fyodor nikolaevich volkov", " для проверки")]
    public void MasksTwoAndThreeWordsInMessage(string before, string name, string after)
    {
        using var aliases = new Pseudonymizer(new byte[32], "contextual-person-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var persons = new EmptyPersonDetector();
        var engine = new PrivacyEngine(policy, aliases, persons);
        var soft = new SoftPartMasker(aliases, policy, persons);
        string source = "{\"message\":\"" + before + name + after + "\"}";

        var strictResult = engine.SanitizeJsonForDisplay(source);
        var softResult = soft.SanitizeJson(source);
        var typedResult = engine.SanitizeTypedLogForDisplay(source);
        using var typed = JsonDocument.Parse(typedResult.Text!);

        Assert.Equal(1, strictResult.ReplacementsByType!["PERSON"]);
        Assert.Equal(1, softResult.ReplacementsByType!["PERSON"]);
        Assert.Equal(1, typedResult.ReplacementsByType!["PERSON"]);
        foreach (string output in new[]
        {
            strictResult.Data!["message"]!.GetValue<string>(),
            softResult.Data!["message"]!.GetValue<string>(),
            typed.RootElement.GetProperty("message").GetString()!
        })
        {
            Assert.StartsWith(before, output);
            Assert.EndsWith(after, output);
            foreach (string token in name.Split(' ')) Assert.DoesNotContain(token, output);
        }
    }

    /// <summary>Leave technical phrases and dictionary-looking text outside a person cue intact.</summary>
    [Theory]
    [InlineData("""{"message":"контакт: резервный канал уведомлений; режим тестовый"}""")]
    [InlineData("""{"message":"исполнитель: очередь проверки платежей; задача завершена"}""")]
    [InlineData("""{"message":"архивная метка: светлана соколова; принято"}""")]
    [InlineData("""{"message":"recipient: payment routing service; status ready"}""")]
    [InlineData("""{"message":"contact: otdel raschetov; archived"}""")]
    public void KeepsTechnicalMessage(string source)
    {
        using var aliases = new Pseudonymizer(new byte[32], "contextual-person-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var persons = new EmptyPersonDetector();
        var engine = new PrivacyEngine(policy, aliases, persons);
        var soft = new SoftPartMasker(aliases, policy, persons);
        Assert.Equal(source, engine.SanitizeTypedLogForDisplay(source).Text);
        Assert.Equal(0, engine.SanitizeJsonForDisplay(source).Replacements);
        Assert.Equal(0, soft.SanitizeJson(source).Replacements);
    }

    private sealed class EmptyPersonDetector : IPersonDetector
    {
        public string Version => "fixture";
        public IReadOnlyList<EntitySpan> Find(string text) => [];
    }
}
