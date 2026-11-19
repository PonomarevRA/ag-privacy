using System.Diagnostics.Metrics;
using Xunit;

namespace AgPrivacy.Tests;

[CollectionDefinition("Process metrics", DisableParallelization = true)]
public sealed class ProcessMetricsCollection;

[Collection("Process metrics")]
public sealed class PrivacyMetricsTests
{
    /// <summary>Cover public modes, redaction totals and the single final outcome of a verified call.</summary>
    [Fact]
    public void ReportsOnlyFixedLabelsAndOneSamplePerCall()
    {
        using var aliases = new Pseudonymizer(new byte[32], "metrics-fixture");
        var policy = PrivacyPolicy.Compile("""{"schemaVersion":"ag-privacy-policy-v1"}"""u8);
        var engine = new PrivacyEngine(policy, aliases);
        var soft = new SoftPartMasker(aliases, policy);
        using var fixture = new VerifiedFixture();
        using var verified = fixture.Open();

        var calls = new List<(string Mode, string Outcome)>();
        var replacements = new Dictionary<string, long>();
        using var listener = CreateListener();
        listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) =>
        {
            Assert.Equal(PrivacyMetrics.DurationName, instrument.Name);
            Assert.Equal("s", instrument.Unit);
            Assert.True(double.IsFinite(value) && value >= 0);
            Assert.Equal(2, tags.Length);
            Assert.Equal("mode", tags[0].Key);
            Assert.Equal("outcome", tags[1].Key);
            calls.Add((Assert.IsType<string>(tags[0].Value), Assert.IsType<string>(tags[1].Value)));
        });
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            Assert.Equal(PrivacyMetrics.ReplacementsName, instrument.Name);
            Assert.Equal("mode", Assert.Single(tags.ToArray()).Key);
            replacements.Add(Assert.IsType<string>(tags[0].Value), value);
        });
        listener.Start();

        Assert.True(engine.SanitizeText("synthetic").Allowed);
        Assert.False(engine.SanitizeText("synthetic", heuristic: true).Allowed);
        Assert.True(engine.SanitizeJson("""{"token":"SYNTHETIC_TOKEN"}""").Allowed);
        Assert.False(engine.SanitizeJsonForDisplay("{").Allowed);
        Assert.True(soft.SanitizeJson("""{"status":"ok"}""").Allowed);
        Assert.False(engine.SanitizeTable([], []).Allowed);
        var faultyEngine = new PrivacyEngine(policy, aliases, new ThrowingPersonDetector());
        Assert.Throws<NotSupportedException>(() => faultyEngine.SanitizeText("synthetic", heuristic: true));
        Assert.True(verified.SanitizeJson("{}").Allowed);
        verified.Dispose();
        Assert.False(verified.SanitizeJson("{}").Allowed);

        Assert.Equal(new[]
        {
            ("strict_text", "ok"), ("heuristic_text", "blocked"), ("strict_json", "ok"),
            ("strict_display", "blocked"), ("soft_part", "ok"), ("strict_table", "blocked"),
            ("heuristic_text", "error"),
            ("verified_strict", "ok"), ("verified_strict", "blocked")
        }, calls);
        Assert.Equal(4, replacements.Count);
        Assert.Equal(1, replacements["strict_text"]);
        Assert.Equal(1, replacements["strict_json"]);
        Assert.Equal(0, replacements["soft_part"]);
        Assert.Equal(0, replacements["verified_strict"]);
    }

    /// <summary>A throwing listener cannot change an allowed or blocked result.</summary>
    [Fact]
    public void ObserverFailureDoesNotAffectMasking()
    {
        using var listener = CreateListener();
        listener.SetMeasurementEventCallback<double>((_, _, _, _) => throw new InvalidOperationException("fixture"));
        listener.Start();
        using var aliases = new Pseudonymizer(new byte[32], "metrics-fixture");
        var soft = new SoftPartMasker(aliases);
        Assert.True(soft.SanitizeJson("{}").Allowed);
        Assert.False(soft.SanitizeJson("{").Allowed);
    }

    /// <summary>Subscribe to the process meter only during this non-parallel test collection.</summary>
    private static MeterListener CreateListener() => new()
    {
        InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == PrivacyMetrics.MeterName) listener.EnableMeasurementEvents(instrument);
        }
    };

    private sealed class ThrowingPersonDetector : IPersonDetector
    {
        public string Version => "fixture";

        /// <summary>Simulate an unexpected detector failure without exposing input.</summary>
        public IReadOnlyList<EntitySpan> Find(string text) => throw new NotSupportedException("fixture");
    }
}
