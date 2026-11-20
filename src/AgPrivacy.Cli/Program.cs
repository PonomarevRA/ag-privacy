using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AgPrivacy;

if (args.Length > 0 && args[0] == "stream-log")
    return await StreamLogAsync(args);

if (args.Length > 0 && args[0] is ("stream-csv" or "stream-xml"))
    return await StreamStructuredAsync(args);

// Host-side data plane only. No consent issuer, disabling switch, network access or synthetic bypass in this binary.
try
{
    if(args.Length==5&&args[0]=="sanitize-verified")
    {
        byte[] publicKey=ReadFile(args[2],512),digest=Convert.FromHexString(args[3]),privateKey=ReadKey(args[4]);
        VerifiedPrivacyModule module;
        try{module=VerifiedPrivacyModule.Load(args[1],publicKey,privateKey,digest);}
        finally{CryptographicOperations.ZeroMemory(privateKey);}
        using(module)
        using(var verifiedInput=new BufferedStream(Console.OpenStandardInput(),16384))
        {
            while(ReadLine(verifiedInput) is { } line)Console.WriteLine(JsonSerializer.Serialize(module.SanitizeJson(line),PrivacyJsonContext.Default.PrivacyResult));
        }
        return 0;
    }
    if(args.Length==2 && args[0]=="benchmark-synthetic")return Benchmark(args[1]);
    if(args.Length is <5 or >6 || args[0]!="sanitize" || args[1] is not ("json" or "text" or "heuristic"))
    {
        Console.Error.WriteLine("usage: sanitize json|text|heuristic POLICY_FILE PRIVATE_KEY_FILE SCOPE [LOCAL_MODEL_FILE]");return 2;
    }
    string mode=args[1];var policy=PrivacyPolicy.Compile(ReadFile(args[2],65536));
    byte[] key=ReadKey(args[3]);Pseudonymizer created;
    try { created=new Pseudonymizer(key,args[4]); }
    finally { CryptographicOperations.ZeroMemory(key); }
    using var aliases=created;
    IPersonDetector? model=args.Length==6 ? MicroPersonModel.Load(ReadFile(args[5],MicroPersonModel.MaximumFileBytes)) : null;
    if(mode=="heuristic" && model is null)throw new ArgumentException("model-required");
    var engine=new PrivacyEngine(policy,aliases,model);
    using var input=new BufferedStream(Console.OpenStandardInput(),16384);
    while(ReadLine(input) is { } line)
    {
        var result=mode=="json" ? engine.SanitizeJson(line) : engine.SanitizeText(line,mode=="heuristic");
        Console.WriteLine(JsonSerializer.Serialize(result,PrivacyJsonContext.Default.PrivacyResult));
    }
    return 0;
}
catch(Exception)
{
    // Even startup/decoder/IO/model errors return fixed metadata; never echo paths, inputs, key bytes or exception messages.
    Console.WriteLine("{\"Allowed\":false,\"SafeForAgent\":false,\"Status\":\"privacy-processing-blocked\"}");return 2;
}

/// <summary>Run a structured display stream with the same private journal contract as stream-log.</summary>
static async Task<int> StreamStructuredAsync(string[] args)
{
    bool csv = args[0] == "stream-csv";
    char delimiter = args.Length == 5 ? ',' : args.Length == 6 && csv ? args[5] switch
    {
        "comma" => ',',
        "semicolon" => ';',
        "tab" => '\t',
        _ => '\0'
    } : '\0';
    if (delimiter == '\0')
    {
        Console.Error.WriteLine("usage: stream-csv POLICY KEY SCOPE NEW_JOURNAL [comma|semicolon|tab] or stream-xml POLICY KEY SCOPE NEW_JOURNAL");
        return 2;
    }

    try
    {
        var policy = PrivacyPolicy.Compile(ReadFile(args[1], 65536));
        byte[] key = ReadKey(args[2]);
        Pseudonymizer created;
        try { created = new Pseudonymizer(key, args[3]); }
        finally { CryptographicOperations.ZeroMemory(key); }
        using var aliases = created;
        await using var journalFile = OpenStreamJournal(args[4]);
        await using var journal = new StreamWriter(journalFile, new UTF8Encoding(false, true));
        using var input = Console.OpenStandardInput();
        using var output = Console.OpenStandardOutput();
        var masker = new StructuredPrivacyMasker(policy, aliases);
        if (csv) await masker.MaskCsvAsync(input, output, delimiter, journal);
        else await masker.MaskXmlAsync(input, output, journal);
        return 0;
    }
    catch
    {
        Console.Error.WriteLine("privacy-stream-blocked");
        return 2;
    }
}

/// <summary>Create a new journal with private access on Unix.</summary>
static FileStream OpenStreamJournal(string path)
{
    var options = new FileStreamOptions
    {
        Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None,
        Options = FileOptions.Asynchronous
    };
    if (!OperatingSystem.IsWindows())
        options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    return new FileStream(path, options);
}

/// <summary>Keep stdout for the masked stream and create a separate private journal.</summary>
static async Task<int> StreamLogAsync(string[] args)
{
    if (!TryReadStreamOptions(args, out int positional, out string? personShadowPath, out string? numericShadowPath, out string? personalIdShadowPath, out string? innPath, out string? kppPath, out string? tokenPath, out string? prosePath, out string? analysis, out string? structuredPath))
    {
        Console.Error.WriteLine("usage: stream-log POLICY_FILE PRIVATE_KEY_FILE SCOPE NEW_JOURNAL_FILE [LOCAL_MODEL_FILE] [--person-context-shadow MODEL] [--numeric-context-shadow MODEL] [--personal-id-shadow MODEL] [--inn-context-shadow MODEL] [--kpp-context-shadow MODEL] [--token-context-shadow MODEL] [--person-prose-model MODEL] [--log-analysis text|structured|mixed] [--structured-person-model MODEL]");
        return 2;
    }

    try
    {
        var policy = PrivacyPolicy.Compile(ReadFile(args[1], 65536));
        byte[] key = ReadKey(args[2]);
        Pseudonymizer created;
        try { created = new Pseudonymizer(key, args[3]); }
        finally { CryptographicOperations.ZeroMemory(key); }
        using var aliases = created;
        IPersonDetector? model = positional == 6
            ? MicroPersonModel.Load(ReadFile(args[5], MicroPersonModel.MaximumFileBytes)) : null;
        var shadow = personShadowPath is null ? null : PersonContextShadow.Load(ReadFile(personShadowPath, PersonContextShadow.ModelBytes));
        var numeric = numericShadowPath is null ? null : NumericContextShadow.Load(ReadFile(numericShadowPath, NumericContextShadow.ModelBytes));
        if (innPath is not null)
            numeric = (numeric ?? NumericContextShadow.Empty()).WithTaxSpecialist(ReadFile(innPath, NumericContextShadow.SpecialistBytes), isInn: true);
        if (kppPath is not null)
            numeric = (numeric ?? NumericContextShadow.Empty()).WithTaxSpecialist(ReadFile(kppPath, NumericContextShadow.SpecialistBytes), isInn: false);
        if (personalIdShadowPath is not null)
            numeric = (numeric ?? NumericContextShadow.Empty()).WithPersonalIdShadow(PersonalIdShadow.Load(ReadFile(personalIdShadowPath, PersonalIdShadow.ModelBytes)));
        var token = tokenPath is null ? null : TokenContextShadow.Load(ReadFile(tokenPath, TokenContextShadow.ModelBytes));
        var prose = prosePath is null ? null : MicroPersonModel.Load(ReadFile(prosePath, MicroPersonModel.MaximumFileBytes));
        StreamingPrivacyMasker pipe;
        if (analysis is null)
            pipe = new StreamingPrivacyMasker(policy, aliases, model, shadow, numeric, token, prose);
        else
        {
            LogAnalysisMode mode = analysis switch
            {
                "text" => LogAnalysisMode.Text,
                "structured" => LogAnalysisMode.Structured,
                _ => LogAnalysisMode.Mixed
            };
            var proseDetector = prose ?? model;
            var structuredDetector = structuredPath is null ? null : MicroPersonModel.Load(ReadFile(structuredPath, MicroPersonModel.MaximumFileBytes));
            pipe = new StreamingPrivacyMasker(policy, aliases, null, shadow, numeric, token, proseDetector, mode, structuredDetector);
        }
        await using var journalFile = OpenStreamJournal(args[4]);
        await using var journal = new StreamWriter(journalFile, new UTF8Encoding(false, true));
        var result = await pipe.MaskAsync(Console.OpenStandardInput(), Console.OpenStandardOutput(), journal);
        if (result.PersonContext is not null || result.NumericContext is not null || result.TokenContext is not null)
            WriteShadowCounts(result);
        return 0;
    }
    catch
    {
        Console.Error.WriteLine("privacy-stream-blocked");
        return 2;
    }
}

/// <summary>Accept each optional model flag once, with an optional positional person detector before the flags.</summary>
static bool TryReadStreamOptions(string[] args, out int positional, out string? person, out string? numeric, out string? personalId, out string? inn, out string? kpp, out string? token, out string? prose, out string? analysis, out string? structured)
{
    person = numeric = personalId = inn = kpp = token = prose = analysis = structured = null;
    positional = Math.Min(args.Length, 5);
    if (positional < 5) return false;
    if (args.Length > positional && !args[positional].StartsWith("--", StringComparison.Ordinal)) positional++;

    for (int i = positional; i < args.Length; i += 2)
    {
        if (i + 1 == args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal)) return false;
        switch (args[i])
        {
            case "--person-context-shadow" when person is null: person = args[i + 1]; break;
            case "--numeric-context-shadow" when numeric is null: numeric = args[i + 1]; break;
            case "--personal-id-shadow" when personalId is null: personalId = args[i + 1]; break;
            case "--inn-context-shadow" when inn is null: inn = args[i + 1]; break;
            case "--kpp-context-shadow" when kpp is null: kpp = args[i + 1]; break;
            case "--token-context-shadow" when token is null: token = args[i + 1]; break;
            case "--person-prose-model" when prose is null: prose = args[i + 1]; break;
            case "--log-analysis" when analysis is null: analysis = args[i + 1]; break;
            case "--structured-person-model" when structured is null: structured = args[i + 1]; break;
            default: return false;
        }
    }
    if (structured is not null && analysis is null) return false;
    if (analysis is not null && analysis is not ("text" or "structured" or "mixed")) return false;
    if (analysis is not null && prose is not null && positional > 5) return false;
    return numeric is null || (inn is null && kpp is null);
}

/// <summary>Write one metadata-only JSON record to stderr, keeping stdout available for the log stream.</summary>
static void WriteShadowCounts(StreamMaskResult result)
{
    using var buffer = new MemoryStream();
    using (var writer = new Utf8JsonWriter(buffer))
    {
        writer.WriteStartObject();
        if (result.PersonContext is { } person)
        {
            writer.WriteStartObject("personContextShadow");
            writer.WriteNumber("candidates", person.Candidates);
            writer.WriteNumber("wouldPreserve", person.WouldPreserve);
            writer.WriteNumber("abstained", person.Abstained);
            writer.WriteEndObject();
        }
        if (result.NumericContext is { } numeric)
        {
            writer.WriteStartObject("numericContextShadow");
            writer.WriteNumber("candidates", numeric.Candidates);
            writer.WriteNumber("inn", numeric.Inn);
            writer.WriteNumber("kpp", numeric.Kpp);
            writer.WriteNumber("personalId", numeric.PersonalId);
            writer.WriteNumber("technical", numeric.Technical);
            writer.WriteNumber("abstained", numeric.Abstained);
            writer.WriteEndObject();
        }
        if (result.PersonalIdContext is { } personalId)
        {
            writer.WriteStartObject("personalIdShadow");
            writer.WriteNumber("reviewed", personalId.Reviewed);
            writer.WriteNumber("proposed", personalId.Proposed);
            writer.WriteEndObject();
        }
        if (result.TokenContext is { } token)
        {
            writer.WriteStartObject("tokenContextShadow");
            writer.WriteNumber("reviewed", token.Reviewed);
            writer.WriteNumber("proposed", token.Proposed);
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }
    Console.Error.WriteLine(Encoding.UTF8.GetString(buffer.GetBuffer().AsSpan(0, (int)buffer.Length)));
}

/// <summary>Open once, check permissions of that exact inode, then read it. Host must also isolate ownership/path from agents.</summary>
static byte[] ReadKey(string path)
{
    using var handle=File.OpenHandle(path,FileMode.Open,FileAccess.Read,FileShare.Read);
    if(!OperatingSystem.IsWindows() && (File.GetUnixFileMode(handle) & (UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)throw new ArgumentException("key-permissions");
    using var stream=new FileStream(handle,FileAccess.Read);
    var buffer=new byte[129];
    try
    {
        int read=0;
        while(read<buffer.Length){int count=stream.Read(buffer,read,buffer.Length-read);if(count==0)break;read+=count;}
        if(read is <32 or >128)throw new ArgumentException("key-size");
        return buffer[..read];
    }
    finally { CryptographicOperations.ZeroMemory(buffer); }
}
/// <summary>Read a fixed-size trusted artifact without FileInfo/ReadAllBytes race or unbounded allocation.</summary>
static byte[] ReadFile(string path,int limit)
{
    using var stream=File.OpenRead(path);var buffer=new byte[limit+1];int read=0;
    while(read<buffer.Length){int n=stream.Read(buffer,read,buffer.Length-read);if(n==0)break;read+=n;}
    if(read>limit)throw new ArgumentException("artifact-limit");return buffer[..read];
}
/// <summary>One complete UTF-8 line before sanitization; overlong/invalid units abort without partial output.</summary>
static string? ReadLine(Stream stream)
{
    using var line=new MemoryStream();
    while(true)
    {
        int b=stream.ReadByte();if(b==-1){if(line.Length==0)return null;break;}if(b==10)break;
        if(line.Length>=PrivacyLimits.InputBytes)throw new ArgumentException("input-limit");line.WriteByte((byte)b);
    }
    string result=new UTF8Encoding(false,true).GetString(line.GetBuffer(),0,(int)line.Length);
    return result.EndsWith('\r')?result[..^1]:result;
}
/// <summary>Reproducible synthetic steady workload, metadata only; production capacity and minimum RSS are not inferred.</summary>
static int Benchmark(string modelPath)
{
    var model=MicroPersonModel.Load(ReadFile(modelPath,MicroPersonModel.MaximumFileBytes));
    var policy=PrivacyPolicy.Compile("{\"schemaVersion\":\"ag-privacy-policy-v1\"}"u8);
    using var aliases=new Pseudonymizer(new byte[32],"synthetic-benchmark");var engine=new PrivacyEngine(policy,aliases,model);
    string input=string.Join(' ',Enumerable.Repeat("Client: Walter Fabricato. klogin=q-1234567 trdacc=SYNTHETIC_ACCOUNT ИНН:991234567890 КПП:991234567 ?owner=TEST_PERSON",8));
    for(int i=0;i<50;i++)engine.SanitizeText(input,true);
    var durations=new double[500];
    for(int i=0;i<durations.Length;i++)
    {
        long start=Stopwatch.GetTimestamp();var result=engine.SanitizeText(input,true);
        if(!result.Allowed)throw new InvalidOperationException("benchmark-blocked");
        durations[i]=Stopwatch.GetElapsedTime(start).TotalMilliseconds;
    }
    Array.Sort(durations);GC.Collect();GC.WaitForPendingFinalizers();
    var report=new JsonObject { ["workload"]="synthetic-heuristic-500x",["inputUtf8Bytes"]=Encoding.UTF8.GetByteCount(input),["modelBytes"]=model.WeightBytes+16,
        ["p50Milliseconds"]=durations[250],["p95Milliseconds"]=durations[475],["managedLiveBytes"]=GC.GetTotalMemory(false),["workingSetBytes"]=Process.GetCurrentProcess().WorkingSet64,
        ["modelVersion"]=model.Version,["qualification"]="local-synthetic-not-production-capacity" };
    Console.WriteLine(report.ToJsonString());return 0;
}
