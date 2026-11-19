using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;
using AgPrivacy;

/// <summary>Expose the library's fixed set of metric series to a local Prometheus scraper.</summary>
internal sealed class PrometheusMetrics : IDisposable
{
    internal const string ContentType = "text/plain; version=0.0.4; charset=utf-8";
    private const string DurationMetric = "ag_privacy_operation_duration_seconds";
    private const string ReplacementsMetric = "ag_privacy_replacements_total";
    private static readonly double[] Boundaries = PrivacyMetrics.DurationBoundaries.ToArray();

    private readonly object gate = new();
    private readonly Dictionary<(string Mode, string Outcome), DurationSeries> durations = new();
    private readonly Dictionary<string, long> replacements = new(StringComparer.Ordinal);
    private readonly MeterListener listener = new();

    /// <summary>Collect only AgPrivacy instruments. The Playground needs no exporter packages or network client.</summary>
    internal PrometheusMetrics()
    {
        listener.InstrumentPublished = static (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == PrivacyMetrics.MeterName &&
                instrument.Name is PrivacyMetrics.DurationName or PrivacyMetrics.ReplacementsName)
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<double>(RecordDuration);
        listener.SetMeasurementEventCallback<long>(RecordReplacements);
        listener.Start();
    }

    /// <summary>Take a consistent copy of each histogram before formatting the scrape response.</summary>
    internal string Collect()
    {
        var durationSnapshot = new List<((string Mode, string Outcome) Labels, DurationSeries Series)>();
        KeyValuePair<string, long>[] replacementsSnapshot;
        lock (gate)
        {
            foreach (var (labels, series) in durations)
                durationSnapshot.Add((labels, new((long[])series.Buckets.Clone(), series.Sum)));
            replacementsSnapshot = replacements.ToArray();
        }

        var output = new StringBuilder();
        output.Append("# HELP " + DurationMetric + " Elapsed time of one masking call in seconds.\n");
        output.Append("# TYPE " + DurationMetric + " histogram\n");
        foreach (var (labels, series) in durationSnapshot)
        {
            string labelText = $"mode=\"{labels.Mode}\",outcome=\"{labels.Outcome}\"";
            long count = 0;
            for (int i = 0; i < Boundaries.Length; i++)
            {
                count += series.Buckets[i];
                output.Append(CultureInfo.InvariantCulture, $"{DurationMetric}_bucket{{{labelText},le=\"{Boundaries[i]}\"}} {count}\n");
            }
            count += series.Buckets[^1];
            output.Append(CultureInfo.InvariantCulture, $"{DurationMetric}_bucket{{{labelText},le=\"+Inf\"}} {count}\n");
            output.Append(CultureInfo.InvariantCulture, $"{DurationMetric}_sum{{{labelText}}} {series.Sum}\n");
            output.Append(CultureInfo.InvariantCulture, $"{DurationMetric}_count{{{labelText}}} {count}\n");
        }

        output.Append("# HELP " + ReplacementsMetric + " Replacements returned by successful masking calls.\n");
        output.Append("# TYPE " + ReplacementsMetric + " counter\n");
        foreach (var (mode, count) in replacementsSnapshot)
            output.Append(CultureInfo.InvariantCulture, $"{ReplacementsMetric}{{mode=\"{mode}\"}} {count}\n");
        return output.ToString();
    }

    /// <summary>Update the bucket for this value. Convert counts to cumulative buckets at scrape time.</summary>
    private void RecordDuration(Instrument instrument, double seconds, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
    {
        if (tags.Length != 2 || tags[0].Key != "mode" || tags[1].Key != "outcome" ||
            tags[0].Value is not string mode || tags[1].Value is not ("ok" or "blocked" or "error"))
            return;
        string outcome = (string)tags[1].Value!;
        int bucket = Array.BinarySearch(Boundaries, seconds);
        if (bucket < 0) bucket = ~bucket;
        lock (gate)
        {
            if (!durations.TryGetValue((mode, outcome), out var series))
            {
                series = new(new long[Boundaries.Length + 1], 0);
                durations.Add((mode, outcome), series);
            }
            series.Buckets[bucket]++;
            series.Sum += seconds;
        }
    }

    /// <summary>Count replacements by mode independently of request latency.</summary>
    private void RecordReplacements(Instrument instrument, long count, ReadOnlySpan<KeyValuePair<string, object?>> tags, object? state)
    {
        if (tags.Length != 1 || tags[0].Key != "mode" || tags[0].Value is not string mode) return;
        lock (gate) replacements[mode] = replacements.GetValueOrDefault(mode) + count;
    }

    public void Dispose() => listener.Dispose();

    private sealed class DurationSeries(long[] buckets, double sum)
    {
        public long[] Buckets { get; } = buckets;
        public double Sum { get; set; } = sum;
    }
}
