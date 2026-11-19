using System.Text;

namespace AgPrivacy;

/// <summary>Parse CSV records across buffer and physical line boundaries with bounded record storage.</summary>
internal sealed class CsvRecords(TextReader input, char delimiter, int recordChars, int maxFields)
{
    private readonly char[] buffer = new char[4096];
    private int offset, length;
    private bool skipLineFeed;

    private enum FieldState { Start, Unquoted, Quoted, Closed }

    /// <summary>Read and validate one logical record, including quoted delimiters and newlines.</summary>
    internal async Task<List<string>?> ReadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var cells = new List<string>();
        var cell = new StringBuilder();
        var state = FieldState.Start;
        int size = 0;
        while (true)
        {
            if (offset == length)
            {
                length = await input.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
                offset = 0;
                if (length == 0)
                {
                    if (state == FieldState.Quoted) throw new InvalidDataException("unclosed-csv-quote");
                    return size == 0 ? null : Finish(cells, cell);
                }
            }
            char ch = buffer[offset++];
            if (skipLineFeed)
            {
                skipLineFeed = false;
                if (ch == '\n') continue;
            }
            if (++size > recordChars) throw new InvalidDataException("csv-record-limit");
            if (state == FieldState.Quoted)
            {
                if (ch == '"') state = FieldState.Closed;
                else cell.Append(ch);
                continue;
            }
            if (ch == delimiter)
            {
                Finish(cells, cell);
                cell.Clear();
                state = FieldState.Start;
            }
            else if (ch is '\r' or '\n')
            {
                skipLineFeed = ch == '\r';
                return Finish(cells, cell);
            }
            else if (ch == '"' && state is FieldState.Start or FieldState.Closed)
            {
                if (state == FieldState.Closed) cell.Append(ch);
                state = FieldState.Quoted;
            }
            else if (ch == '"' || state == FieldState.Closed)
                throw new InvalidDataException("invalid-csv-quote");
            else
            {
                cell.Append(ch);
                state = FieldState.Unquoted;
            }
        }
    }

    /// <summary>Limit the number of fields independently of the total record length.</summary>
    private List<string> Finish(List<string> cells, StringBuilder cell)
    {
        if (cells.Count >= maxFields) throw new InvalidDataException("csv-field-limit");
        cells.Add(cell.ToString());
        return cells;
    }
}
