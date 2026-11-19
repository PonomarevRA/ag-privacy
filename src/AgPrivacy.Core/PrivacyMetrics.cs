using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace AgPrivacy;

/// <summary>Process-wide masking metrics. The host chooses whether and where to export them.</summary>
public static class PrivacyMetrics
{
    public const string MeterName = "AgPrivacy";
    public const string DurationName = "ag_privacy.operation.duration";
    public const string ReplacementsName = "ag_privacy.replacements";

    /// <summary>Recommended duration histogram boundaries in seconds, covering sub-millisecond masking.</summary>
    public static IReadOnlyList<double> DurationBoundaries { get; } =
        Array.AsReadOnly(new double[] { 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005,
            0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 });

    /// <summary>Avoid reading the clock when no host is collecting these instruments.</summary>
    internal static long Start()
    {
        try
        {
            return Instruments.Duration.Enabled || Instruments.Replacements.Enabled ? Stopwatch.GetTimestamp() : -1;
        }
        catch (TypeInitializationException)
        {
            // An observer can also fail while instruments are being published.
            return -1;
        }
    }

    /// <summary>Publish fixed labels and aggregates. A failed observer cannot change a masking result.</summary>
    internal static void Record(long started, string mode, PrivacyResult? result)
    {
        if (started < 0) return;

        string outcome = "error";
        if (result is not null) outcome = result.Allowed ? "ok" : "blocked";
        try
        {
            Instruments.Duration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds, new("mode", mode), new("outcome", outcome));
            if (result is { Allowed: true })
                Instruments.Replacements.Add(result.Replacements, new KeyValuePair<string, object?>("mode", mode));
        }
        catch (Exception)
        {
            // MeterListener runs synchronously. Never surface exporter failures on the masking path.
        }
    }

    private static class Instruments
    {
        private static readonly Meter Meter = new(MeterName);
        internal static readonly Histogram<double> Duration = Meter.CreateHistogram<double>(
            DurationName, "s", "Elapsed time of one masking call.",
            advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = DurationBoundaries });
        internal static readonly Counter<long> Replacements = Meter.CreateCounter<long>(
            ReplacementsName, description: "Replacements returned by successful masking calls.");
    }
}
