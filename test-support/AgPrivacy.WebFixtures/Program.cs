// Generate synthetic cross-runtime reference cases without training or changing model weights.
using System.Text.Json;
using AgPrivacy;

if (args.Length != 1) return 2;
var models = new Dictionary<string, object>();
string[] starts = ["", "Контакт: ", "After the call ", "service account login=", "Запись: "];
string[] values = ["алина зорничева", "Роман Левчанов", "Alina Levchanova", "levchanov_io",
    "Зорничева А.М.", "API gateway", "архивный модуль", "Maria Sоkolova", "🙂", "\\u0410"];
string[] ends = ["", "; approved", " подтвердила изменение.", " requested a call."];
foreach (string stem in new[] { "person-default", "person-prose" })
{
    var model = MicroPersonModel.Load(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, stem + ".bin")));
    var examples = new List<object>();
    foreach (string start in starts)
    foreach (string value in values)
    foreach (string end in ends)
    {
        string text = start + value + end;
        examples.Add(new { text, spans = model.Find(text).Select(span => new { start = span.Start, length = span.Length, type = span.Type }) });
    }
    models.Add(stem, new { sha256 = model.Version, examples });
}
const string unicode = "İ I ı Σ ΟΣ ς Straße ẞ K 𐐀 ١٢ ²¼ é";
var tokens = MicroPersonModel.Tokenize(unicode);
var tokenFixture = tokens.Select((token, index) => new
{
    start = token.Start, length = token.Length, word = token.Word, lower = token.Lower,
    features = Enumerable.Range(0, 3).Select(previous => MicroPersonModel.Features(tokens, index, previous, 8192))
});
var fixture = new { models, unicode = new { text = unicode, tokens = tokenFixture } };
File.WriteAllText(args[0], JsonSerializer.Serialize(fixture, new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine("Generated 400 synthetic model comparisons and Unicode feature fixtures.");
return 0;
