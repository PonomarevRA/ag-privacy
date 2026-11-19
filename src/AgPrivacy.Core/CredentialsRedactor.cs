using System.Text;
using System.Diagnostics;
using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
namespace AgPrivacy;

/// <summary>Explicit human-selected reduced protection, not general depersonalization. No NER needed; preserves non-credential data.</summary>
internal sealed partial class CredentialsRedactor(Pseudonymizer aliases,PrivacyPolicy policy)
{
    /// <summary>Expose the compiled matches to selective log masking.</summary>
    internal static MatchCollection AuthorizationMatches(string text) => Bearer().Matches(text);

    [GeneratedRegex("(?<name>[\\p{L}_][\\p{L}\\p{N}_-]{0,95})\\s*[:=]\\s*(?:\"(?<quoted>[^\"\\r\\n]*)\"|(?<value>[^\\s&;,<>{}\\r\\n]+))",RegexOptions.CultureInvariant,100)]
    private static partial Regex Labeled();
    [GeneratedRegex("\\b(?:Bearer|Basic)\\s+(?<token>[A-Za-z0-9._~+/=-]{1,8192})",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,100)]
    private static partial Regex Bearer();
    /// <summary>Detect an explicitly labeled authorization token.</summary>
    internal static bool ContainsAuthorizationToken(string text) => Bearer().IsMatch(text);

    [GeneratedRegex("<input\\b(?:[^\"'<>]|\"[^\"]*\"|'[^']*'){0,4096}>",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,100)]
    private static partial Regex Inputs();
    [GeneratedRegex("(?<name>type|name|id|value)\\s*=\\s*(?:\"(?<double>[^\"]*)\"|'(?<single>[^']*)'|(?<plain>[^\\s>]+))",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,100)]
    private static partial Regex Attribute();
    private static readonly HashSet<string> LoginNames=new(StringComparer.Ordinal){"login","user","userid","username","userlogin","klogin","email","логин"};
    private static readonly FrozenSet<string> SecretNames=new[]{"password","passwd","pwd","secret","apikey","accesstoken","refreshtoken","privatekey","authorization","bearer","token","cookie","setcookie","connectionstring","csrf","csrftoken","xsrf","xsrftoken","requestverificationtoken","authenticitytoken","sessionid","sessiontoken"}.ToFrozenSet(StringComparer.Ordinal);
    private readonly Stopwatch elapsed=Stopwatch.StartNew();
    private int count,nodes;
    /// <summary>Walk the complete bounded JSON unit. Form metadata can add masking, never enable a less protective mode.</summary>
    internal (JsonNode? Data,int Count) Redact(string json)
    {
        var node=JsonNode.Parse(json,new JsonNodeOptions(),new JsonDocumentOptions{MaxDepth=PrivacyLimits.Depth});
        return(Walk(node,null,false,0),count);
    }
    private JsonNode? Walk(JsonNode? node,string? field,bool form,int depth)
    {
        CheckBudget();
        if(++nodes>PrivacyLimits.Nodes || depth>PrivacyLimits.Depth)throw new InvalidOperationException("document-limit");
        if(node is null)return null;
        if(field is not null&&(SecretField(field)||(form&&LoginField(field))))return MaskValue(node);
        if(node is JsonObject obj)
        {
            bool sensitiveValue=false;
            foreach(var item in obj)
            {
                string normalized=PrivacyPolicy.NormalizeField(item.Key);
                if(item.Value is JsonValue v && v.TryGetValue<string>(out var value))
                {
                    if(normalized=="type"&&value.Equals("password",StringComparison.OrdinalIgnoreCase))sensitiveValue=true;
                    if(form&&normalized is "name" or "id"&&LoginField(value))sensitiveValue=true;
                    if(normalized is "name" or "id"&&SecretField(value))sensitiveValue=true;
                }
            }
            var result=new JsonObject();
            foreach(var item in obj)
            {
                string name=PrivacyPolicy.NormalizeField(item.Key);
                bool childForm=form||name is "form" or "forms" or "formfields" or "inputs";
                if((SecretField(item.Key)||(form&&LoginField(name))||(sensitiveValue&&name=="value")))
                {result[MaskText(item.Key)]=item.Value is null?null:MaskValue(item.Value);continue;}
                result[MaskText(item.Key)]=Walk(item.Value,item.Key,childForm,depth+1);
            }
            return result;
        }
        if(node is JsonArray array)
        {
            var result=new JsonArray();foreach(var value in array)result.Add(Walk(value,field,form,depth+1));return result;
        }
        if(field is not null && SecretField(field))return MaskValue(node);
        if(node is JsonValue atom&&atom.TryGetValue<string>(out var text))return JsonValue.Create(MaskText(text));
        return node.DeepClone();
    }
    /// <summary>Whole-unit deadline complements per-regex timeouts; never return a partial redaction after budget exhaustion.</summary>
    private void CheckBudget(){if(elapsed.ElapsedMilliseconds>250)throw new InvalidOperationException("credential-analysis-limit");}
    /// <summary>Check the shared deadline before/after enumeration, including regexes that return no matches.</summary>
    private IEnumerable<Match> Matches(Regex regex,string text)
    {
        CheckBudget();
        foreach(Match match in regex.Matches(text)){CheckBudget();yield return match;}
        CheckBudget();
    }
    private bool LoginField(string name)=>LoginNames.Contains(PrivacyPolicy.NormalizeField(name))||policy.FieldType(name)=="KLOGIN";
    private bool SecretField(string name)=>SecretNames.Contains(PrivacyPolicy.NormalizeField(name))||policy.FieldType(name)=="SECRET";
    private JsonNode? MaskValue(JsonNode node)
    {
        string text=node is JsonValue atom&&atom.TryGetValue<string>(out var value)?value:node.ToJsonString();
        count++;return JsonValue.Create(aliases.Replace("SECRET",text));
    }
    /// <summary>Mask recognized token formats, secret labels/Bearer and input value attributes for password/login controls.</summary>
    private string MaskText(string text)
    {
        CheckBudget();
        var spans=new List<EntitySpan>();
        foreach(var rule in GeneratedRules.All)
            if(rule.Type=="SECRET")foreach(Match m in Matches(rule.Pattern,text))spans.Add(new(m.Index,m.Length,"SECRET"));
        foreach(Match m in Matches(Labeled(),text))
            if(SecretField(m.Groups["name"].Value))
            {var value=m.Groups["quoted"].Success?m.Groups["quoted"]:m.Groups["value"];if(value.Length>0)spans.Add(new(value.Index,value.Length,"SECRET"));}
        foreach(Match m in Matches(Bearer(),text)){var value=m.Groups["token"];spans.Add(new(value.Index,value.Length,"SECRET"));}
        foreach(Match input in Matches(Inputs(),text))
        {
            bool sensitive=false;var values=new List<Group>();
            foreach(Match attr in Matches(Attribute(),input.Value))
            {
                var value=attr.Groups["double"].Success?attr.Groups["double"]:attr.Groups["single"].Success?attr.Groups["single"]:attr.Groups["plain"];
                string name=attr.Groups["name"].Value.ToLowerInvariant();
                if(name=="type"&&value.Value.Equals("password",StringComparison.OrdinalIgnoreCase))sensitive=true;
                if(name is "name" or "id"&&(LoginField(value.Value)||SecretField(value.Value)))sensitive=true;
                if(name=="value")values.Add(value);
            }
            if(sensitive)foreach(var value in values)if(value.Length>0)spans.Add(new(input.Index+value.Index,value.Length,"SECRET"));
        }
        if(spans.Count>PrivacyLimits.Entities)throw new InvalidOperationException("entity-limit");
        spans.Sort((a,b)=>a.Start.CompareTo(b.Start));var merged=new List<EntitySpan>();
        foreach(var span in spans)
        {
            if(merged.Count==0||span.Start>=merged[^1].Start+merged[^1].Length){merged.Add(span);continue;}
            var before=merged[^1];merged[^1]=new(before.Start,Math.Max(before.Start+before.Length,span.Start+span.Length)-before.Start,"SECRET");
        }
        var result=new StringBuilder();int offset=0;
        foreach(var span in merged){result.Append(text,offset,span.Start-offset);result.Append(aliases.Replace("SECRET",text.Substring(span.Start,span.Length)));offset=span.Start+span.Length;count++;}
        result.Append(text,offset,text.Length-offset);CheckBudget();return result.ToString();
    }
}
