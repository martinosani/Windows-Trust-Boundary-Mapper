using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Output
{
    internal enum ConsoleAlignment
    {
        Left,
        Right
    }

    internal sealed class ConsoleTableOptions
    {
        /// <summary>Maximum rows to consider for auto-width calculation (performance guard).</summary>
        public int WidthSampleSize { get; init; } = 200;

        /// <summary>Maximum rows to print. Null means no limit.</summary>
        public int? MaxRowsToPrint { get; init; }

        /// <summary>Column separator between fields.</summary>
        public string Separator { get; init; } = "  ";

        /// <summary>Whether to print a header row.</summary>
        public bool PrintHeader { get; init; } = true;

        /// <summary>Whether to print a separator row under the header.</summary>
        public bool PrintHeaderSeparator { get; init; } = true;

        /// <summary>Whether to print an extra blank line after the table.</summary>
        public bool TrailingBlankLine { get; init; } = true;
    }

    internal sealed class ConsoleTableColumn<T>
    {
        public string Header { get; }
        public Func<T, object?> Selector { get; }
        public ConsoleAlignment Align { get; }
        public int? MaxWidth { get; }
        public int MinWidth { get; }

        public ConsoleTableColumn(
            string header,
            Func<T, object?> selector,
            ConsoleAlignment align = ConsoleAlignment.Left,
            int? maxWidth = null,
            int minWidth = 0)
        {
            Header = ConsoleText.OneLine(header);
            Selector = selector ?? throw new ArgumentNullException(nameof(selector));
            Align = align;
            MaxWidth = maxWidth;
            MinWidth = Math.Max(0, minWidth);
        }
    }

    internal sealed class ConsoleTable<T>
    {
        private readonly List<ConsoleTableColumn<T>> _columns = new();

        public ConsoleTable<T> AddColumn(
            string header,
            Func<T, object?> selector,
            ConsoleAlignment align = ConsoleAlignment.Left,
            int? maxWidth = null,
            int minWidth = 0)
        {
            _columns.Add(new ConsoleTableColumn<T>(header, selector, align, maxWidth, minWidth));
            return this;
        }

        public void Write(IEnumerable<T> rows, ConsoleTableOptions? options = null)
        {
            options ??= new ConsoleTableOptions();

            if (rows is null) throw new ArgumentNullException(nameof(rows));
            if (_columns.Count == 0) return;

            var rowList = rows as IList<T> ?? rows.ToList();

            // Apply print limit
            IEnumerable<T> rowsToPrint = rowList;
            if (options.MaxRowsToPrint is int max && max >= 0)
                rowsToPrint = rowList.Take(max);

            // Sample rows for width computation (avoid O(n) on huge lists)
            var sample = rowList.Take(Math.Max(0, options.WidthSampleSize)).ToList();

            var widths = ComputeWidths(sample);

            if (options.PrintHeader)
            {
                WriteHeader(widths, options);
                if (options.PrintHeaderSeparator)
                    WriteHeaderSeparator(widths, options);
            }

            foreach (var row in rowsToPrint)
            {
                WriteRow(row, widths, options);
            }

            if (options.TrailingBlankLine)
                Console.WriteLine();
        }

        private int[] ComputeWidths(IReadOnlyList<T> sampleRows)
        {
            var widths = new int[_columns.Count];

            for (int i = 0; i < _columns.Count; i++)
            {
                var col = _columns[i];

                int w = col.Header.Length;
                w = Math.Max(w, col.MinWidth);

                foreach (var row in sampleRows)
                {
                    string cell = ConsoleText.Safe(col.Selector(row));
                    w = Math.Max(w, cell.Length);
                }

                if (col.MaxWidth.HasValue)
                    w = Math.Min(w, col.MaxWidth.Value);

                widths[i] = w;
            }

            return widths;
        }

        private void WriteHeader(int[] widths, ConsoleTableOptions options)
        {
            var cells = new string[_columns.Count];

            for (int i = 0; i < _columns.Count; i++)
            {
                var col = _columns[i];
                var w = widths[i];
                var text = ConsoleText.Truncate(col.Header, w);

                cells[i] = Pad(text, w, ConsoleAlignment.Left);
            }

            Console.WriteLine(string.Join(options.Separator, cells));
        }

        private void WriteHeaderSeparator(int[] widths, ConsoleTableOptions options)
        {
            var cells = new string[_columns.Count];
            for (int i = 0; i < _columns.Count; i++)
            {
                cells[i] = new string('-', widths[i]);
            }
            Console.WriteLine(string.Join(options.Separator, cells));
        }

        private void WriteRow(T row, int[] widths, ConsoleTableOptions options)
        {
            var cells = new string[_columns.Count];

            for (int i = 0; i < _columns.Count; i++)
            {
                var col = _columns[i];
                var w = widths[i];

                string raw = ConsoleText.Safe(col.Selector(row));
                string text = ConsoleText.Truncate(raw, w);

                cells[i] = Pad(text, w, col.Align);
            }

            Console.WriteLine(string.Join(options.Separator, cells));
        }

        private static string Pad(string s, int width, ConsoleAlignment align)
        {
            if (s.Length >= width)
                return s;

            return align == ConsoleAlignment.Right
                ? s.PadLeft(width)
                : s.PadRight(width);
        }
    }
}

