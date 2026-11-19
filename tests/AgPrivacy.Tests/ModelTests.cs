using AgPrivacy;
using Xunit;
namespace AgPrivacy.Tests;
public class ModelTests
{
    [Fact]
    public void ModelBinaryIsBoundedVersionedAndNeverAuthorizesRawText()
    {
        byte[] bytes=MicroPersonModel.Encode(256,new short[256*3]);var model=MicroPersonModel.Load(bytes);
        Assert.Equal(1536,model.WeightBytes);Assert.Empty(model.Find("Synthetic Unknown Person"));
        bytes[12]=2;Assert.Throws<ArgumentException>(()=>MicroPersonModel.Load(bytes));
        Assert.Throws<ArgumentException>(()=>MicroPersonModel.Load(new byte[MicroPersonModel.MaximumFileBytes+1]));
        Assert.Throws<InvalidOperationException>(()=>MicroPersonModel.Tokenize(new string('a',257)));
    }
    [Fact]
    public void ShippedModelDetectsSyntheticHeldOutNameButNeverCertifiesText()
    {
        byte[] bytes=File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,"person-default.bin"));
        var model=MicroPersonModel.Load(bytes);const string text="Client: Walter Fabricato. Account ready.";
        Assert.Contains(model.Find(text),s=>text.Substring(s.Start,s.Length)=="Walter Fabricato");
        using var aliases=new Pseudonymizer(new byte[32],"test");
        var policy=PrivacyPolicy.Compile("{\"schemaVersion\":\"ag-privacy-policy-v1\"}"u8);
        var result=new PrivacyEngine(policy,aliases,model).SanitizeText(text,true);
        Assert.True(result.Allowed);Assert.False(result.SafeForAgent);Assert.DoesNotContain("Walter Fabricato",result.Text);
    }
    [Fact]
    public void TokenizerKeepsOffsetsInsidePathsAndQuery()
    {
        const string text="/people/Борис Эталонов/?owner=Walter Fabricato";
        var tokens=MicroPersonModel.Tokenize(text);
        foreach(var t in tokens)Assert.Equal(t.Word,text.Substring(t.Start,t.Length));
        Assert.Contains(tokens,t=>t.Word=="Борис");Assert.Contains(tokens,t=>t.Word=="Walter");
    }
}
