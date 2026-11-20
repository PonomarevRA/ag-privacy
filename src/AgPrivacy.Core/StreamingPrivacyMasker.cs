using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AgPrivacy;

/// <summary>One opaque mapping record. Id is a keyed identifier, never the original text.</summary>
public sealed record StreamReplacement(string Id, string Rule, string Replacement);

/// <summary>Result counters for a display-only UTF-8 stream.</summary>
public sealed record StreamMaskResult(long Replacements, long ConservativeMasks)
{
    public bool SafeForAgent => false;
    /// <summary>Counts all structured replacements, including occurrences deduplicated in the journal.</summary>
    public IReadOnlyDictionary<string, long>? ReplacementsByType { get; init; }
    public PersonContextCounts? PersonContext { get; init; }
    public NumericContextCounts? NumericContext { get; init; }
    public PersonalIdShadowCounts? PersonalIdContext { get; init; }
    public TokenContextCounts? TokenContext { get; init; }
}

/// <summary>Mask a UTF-8 text stream through bounded overlapping windows.</summary>
public sealed class StreamingPrivacyMasker(PrivacyPolicy policy, Pseudonymizer aliases, IPersonDetector? persons, PersonContextShadow? personContext, NumericContextShadow? numericContext, TokenContextShadow? tokenContext)
{
    public StreamingPrivacyMasker(PrivacyPolicy policy, Pseudonymizer aliases, IPersonDetector? persons = null)
        : this(policy, aliases, persons, null, null) { }

    public StreamingPrivacyMasker(PrivacyPolicy policy, Pseudonymizer aliases, IPersonDetector? persons,
        PersonContextShadow? personContext) : this(policy, aliases, persons, personContext, null) { }

    /// <summary>Create the stream with existing person and numeric observers.</summary>
    public StreamingPrivacyMasker(PrivacyPolicy policy, Pseudonymizer aliases, IPersonDetector? persons,
        PersonContextShadow? personContext, NumericContextShadow? numericContext)
        : this(policy, aliases, persons, personContext, numericContext, null) { }

    private const int ReadBuffer = 4096;
    private const int Block = 2048;
    private const int Context = 2048;
    private const int JournalCacheSize = 4096;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private readonly TextRedactor redactor = new(aliases, policy, persons);

    /// <summary>Use the optional prose detector only on log message candidates the base detector misses.</summary>
    public StreamingPrivacyMasker(PrivacyPolicy policy, Pseudonymizer aliases, IPersonDetector? persons,
        PersonContextShadow? personContext, NumericContextShadow? numericContext, TokenContextShadow? tokenContext,
        IPersonDetector? proseModel) : this(policy, aliases, persons, personContext, numericContext, tokenContext)
    {
        redactor = new(aliases, policy, persons, proseModel);
    }

    /// <summary>Route an explicit offline analysis mode across independently loaded prose and structured detectors.</summary>
    public StreamingPrivacyMasker(PrivacyPolicy policy, Pseudonymizer aliases, IPersonDetector? persons,
        PersonContextShadow? personContext, NumericContextShadow? numericContext, TokenContextShadow? tokenContext,
        IPersonDetector? proseModel, LogAnalysisMode analysisMode, IPersonDetector? structuredDetector)
        : this(policy, aliases, persons, personContext, numericContext, tokenContext, proseModel)
    {
        redactor = new(aliases, policy, persons, proseModel, structuredDetector, analysisMode);
    }

    /// <summary>
    /// Read and write incrementally without a whole-stream byte limit. Caller owns the streams and optional
    /// JSONL journal. A failing read or write can leave an already emitted prefix at the destination.
    /// </summary>
    public async Task<StreamMaskResult> MaskAsync(Stream input, Stream output, TextWriter? journal = null,
        CancellationToken cancellationToken = default)
    {
        using var reader = new StreamReader(input, StrictUtf8, detectEncodingFromByteOrderMarks: false,
            bufferSize: ReadBuffer, leaveOpen: true);
        await using var writer = new StreamWriter(output, StrictUtf8, ReadBuffer, leaveOpen: true);
        using var recent = new RecentStreamNames();
        var state = new State(numericContext);
        var buffer = new char[ReadBuffer];
        try
        {
            int read;
            do
            {
                read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                state.Pending.Append(buffer, 0, read);
                bool eof = read == 0;
                while (state.Pending.Length > 0)
                {
                    int length = state.Pending.Length;
                    // Keep a trailing high surrogate for the next read without deferring the rest.
                    if (!eof && char.IsHighSurrogate(state.Pending[^1])) length--;
                    if (!eof && length < Block + Context) break;
                    cancellationToken.ThrowIfCancellationRequested();
                    await CommitAsync(state, recent, writer, journal, length, eof, cancellationToken).ConfigureAwait(false);
                }
            } while (read != 0);
        }
        finally { Array.Clear(buffer); }
        return new(state.Replacements, state.ConservativeMasks)
        {
            PersonContext = personContext is null ? null : new(state.Candidates, state.WouldPreserve, state.Abstained),
            NumericContext = state.NumericCounts is null ? null : SummarizeNumeric(state.NumericCounts),
            TokenContext = tokenContext is null ? null : new(state.TokenReviewed, state.TokenProposed),
            PersonalIdContext = numericContext?.HasPersonalIdShadow == true
                ? new(state.NumericCounts![NumericContextShadow.PersonalIdReviewed], state.NumericCounts[NumericContextShadow.PersonalIdProposed])
                : null
        };
    }

    /// <summary>Choose a stable cut, emit one region, and keep only a bounded raw context suffix.</summary>
    private async Task CommitAsync(State state, RecentStreamNames recent, TextWriter output,
        TextWriter? journal, int length, bool eof, CancellationToken cancellationToken)
    {
        string pending = state.Pending.ToString(0, length);
        if (state.DroppingToken)
        {
            int whitespace = FirstWhitespace(pending);
            int consumed = whitespace < 0 ? pending.Length : whitespace;
            state.Pending.Remove(0, consumed);
            state.DroppingToken = whitespace < 0;
            return;
        }

        int cut = eof ? pending.Length : FindCut(pending, Math.Min(Block, pending.Length - Context));
        if (cut == 0)
        {
            int whitespace = FirstWhitespace(pending);
            state.DroppingToken = whitespace < 0;
            await FallbackAsync(state, output, whitespace < 0 ? pending.Length : whitespace, cancellationToken).ConfigureAwait(false);
            return;
        }

        string window = string.Concat(state.History, pending);
        int from = state.History.Length;
        int end = from + cut;
        List<EntitySpan> spans;
        List<LogMessageRange>? messages = personContext is null && numericContext is null && tokenContext is null ? null : [];
        try
        {
            var found = redactor.FindTypedLogSpans(window, messages);
            recent.Learn(window, found, from);
            recent.AddMatches(window, from, found);
            if (found.Count > PrivacyLimits.Entities) throw new InvalidOperationException("entity-limit");
            spans = TextRedactor.MergeSpans(found);
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or RegexMatchTimeoutException or JsonException)
        {
            await FallbackAsync(state, output, cut, cancellationToken).ConfigureAwait(false);
            return;
        }

        foreach (var span in spans)
        {
            int last = span.Start + span.Length;
            if (span.Start >= end) break;
            if (last <= end) continue;

            // Defer the entire match if possible. If it starts at the frontier, commit it as a unit.
            if (span.Start > from) end = span.Start;
            else if (eof || last <= window.Length - Context / 2) end = last;
            else
            {
                await FallbackAsync(state, output, cut, cancellationToken).ConfigureAwait(false);
                return;
            }
            break;
        }

        await WriteRegionAsync(state, window, from, end, spans, output, journal, cancellationToken).ConfigureAwait(false);
        if (personContext is not null && messages is { Count: > 0 })
            ObserveCommitted(state, window, from, end, spans, messages, personContext);
        if (numericContext is not null && messages is { Count: > 0 })
            ObserveNumeric(state.NumericCounts!, window, from, end, messages, numericContext);
        if (tokenContext is not null && messages is { Count: > 0 })
            ObserveTokens(state, window, from, end, messages, spans, tokenContext);
        int historyStart = Math.Max(0, end - Context);
        if (historyStart < end && char.IsLowSurrogate(window[historyStart])) historyStart++;
        state.History = window[historyStart..end];
        state.Pending.Remove(0, end - from);
    }

    /// <summary>Collect token observations after the active masking decisions have been emitted.</summary>
    private static void ObserveTokens(State state, string text, int from, int end, List<LogMessageRange> messages,
        List<EntitySpan> spans, TokenContextShadow model)
    {
        foreach (var message in messages)
        {
            if (message.Start >= end) break;
            try
            {
                var counts = model.Observe(text, message, from, end, spans);
                state.TokenReviewed += counts.Reviewed;
                state.TokenProposed += counts.Proposed;
            }
            catch (Exception error) when (error is ArgumentException or InvalidOperationException or RegexMatchTimeoutException)
            {
                // An optional observation is allowed to abstain without changing the stream.
            }
        }
    }

    /// <summary>Observe complete message ranges after emitting the original masking decisions.</summary>
    private static void ObserveNumeric(long[] counts, string text, int from, int end,
        List<LogMessageRange> messages, NumericContextShadow model)
    {
        foreach (var message in messages)
        {
            if (message.Start >= end) break;
            if (message.End <= from) continue;
            try { model.Observe(text, message, from, end, counts); }
            catch (Exception error) when (error is ArgumentException or InvalidOperationException or RegexMatchTimeoutException)
            {
                // Shadow analysis is optional and must never interrupt streaming output.
            }
        }
    }

    /// <summary>Expose aggregate class counts without source values or locations.</summary>
    private static NumericContextCounts SummarizeNumeric(long[] counts) => new(
        counts[(int)NumericContextKind.Inn] + counts[(int)NumericContextKind.Kpp] +
        counts[(int)NumericContextKind.PersonalId] + counts[(int)NumericContextKind.Technical] +
        counts[(int)NumericContextKind.Unknown], counts[(int)NumericContextKind.Inn], counts[(int)NumericContextKind.Kpp],
        counts[(int)NumericContextKind.PersonalId], counts[(int)NumericContextKind.Technical],
        counts[(int)NumericContextKind.Unknown]);

    /// <summary>Count only committed heuristic spans. Overlapping windows must not count a decision twice.</summary>
    private static void ObserveCommitted(State state, string text, int from, int end, List<EntitySpan> spans,
        List<LogMessageRange> messages, PersonContextShadow model)
    {
        int message = 0;
        foreach (var span in spans)
        {
            if (span.Start >= end) break;
            if (span.Start < from || span.Start + span.Length > end || !IsContextCandidate(span)) continue;

            while (message < messages.Count && messages[message].End <= span.Start) message++;
            if (message == messages.Count) break;
            var range = messages[message];
            if (span.Start < range.Start || span.Start + span.Length > range.End) continue;

            state.Candidates++;
            switch (model.Review(text, range, span))
            {
                case ContextVerdict.Preserve: state.WouldPreserve++; break;
                case ContextVerdict.Abstain: state.Abstained++; break;
            }
        }
    }

    /// <summary>Exclude explicit schema matches and propagated repeat matches from the experiment.</summary>
    internal static bool IsContextCandidate(EntitySpan span) => span.Type == "PERSON" && span.Priority is 0 or 50;

    /// <summary>Copy source outside selected intervals and publish only committed replacement records.</summary>
    private async Task WriteRegionAsync(State state, string text, int from, int end, List<EntitySpan> spans,
        TextWriter output, TextWriter? journal, CancellationToken cancellationToken)
    {
        var result = new StringBuilder(end - from);
        var records = new List<StreamReplacement>();
        int offset = from;
        foreach (var span in spans)
        {
            int last = span.Start + span.Length;
            if (last <= from) continue;
            if (span.Start >= end) break;
            int first = Math.Max(span.Start, from);
            result.Append(text, offset, first - offset);
            if (span.Start < from)
            {
                result.Append(SoftPartFormats.FullMask);
                state.ConservativeMasks++;
            }
            else
            {
                var (rule, replacement, id) = redactor.MaskSpan(text, span, display: true, substitute: true,
                    journal: journal is not null);
                result.Append(replacement);
                if (id is not null && state.MarkJournal(id))
                    records.Add(new(id, rule, replacement));
            }
            state.Replacements++;
            offset = last;
        }
        result.Append(text, offset, end - offset);
        await output.WriteAsync(result.ToString().AsMemory(), cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (journal is null || records.Count == 0) return;
        foreach (var record in records)
        {
            string line = JsonSerializer.Serialize(record, PrivacyJsonContext.Default.StreamReplacement);
            await journal.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
        }
        await journal.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Mask an unanalyzable region and advance without replaying its original text.</summary>
    private static async Task FallbackAsync(State state, TextWriter output, int count, CancellationToken cancellationToken)
    {
        string mask = count > 0 && state.Pending[count - 1] == '\n'
            ? (count > 1 && state.Pending[count - 2] == '\r' ? SoftPartFormats.FullMask + "\r\n" : SoftPartFormats.FullMask + "\n")
            : SoftPartFormats.FullMask;
        await output.WriteAsync(mask.AsMemory(), cancellationToken).ConfigureAwait(false);
        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        state.Pending.Remove(0, count);
        state.History = "";
        state.Replacements++;
        state.ConservativeMasks++;
    }

    /// <summary>Prefer a nearby line ending, then a whitespace boundary that cannot split a token.</summary>
    private static int FindCut(string text, int limit)
    {
        for (int i = limit - 1; i >= Math.Max(0, limit - 256); i--)
            if (text[i] == '\n') return i + 1;
        for (int i = limit - 1; i >= 0; i--)
            if (char.IsWhiteSpace(text[i])) return i + 1;
        return 0;
    }

    /// <summary>Find the next place after an oversized token where ordinary scanning can resume.</summary>
    private static int FirstWhitespace(string text)
    {
        for (int i = 0; i < text.Length; i++)
            if (char.IsWhiteSpace(text[i])) return i;
        return -1;
    }

    private sealed class State(NumericContextShadow? numericContext)
    {
        internal readonly long[]? NumericCounts = numericContext is null ? null : new long[NumericContextShadow.Outcomes + (numericContext.HasPersonalIdShadow ? 2 : 0)];
        internal readonly StringBuilder Pending = new(Block * 3);
        internal string History = "";
        internal bool DroppingToken;
        internal long Replacements;
        internal long Candidates;
        internal long WouldPreserve;
        internal long Abstained;
        internal long ConservativeMasks;
        internal long TokenReviewed;
        internal long TokenProposed;
        private readonly Queue<string> journalOrder = new();
        private readonly HashSet<string> journalSeen = new(StringComparer.Ordinal);

        /// <summary>Bound journal deduplication; eviction never changes the mask's keyed identity.</summary>
        internal bool MarkJournal(string id)
        {
            if (!journalSeen.Add(id)) return false;
            journalOrder.Enqueue(id);
            if (journalOrder.Count > JournalCacheSize) journalSeen.Remove(journalOrder.Dequeue());
            return true;
        }
    }
}
