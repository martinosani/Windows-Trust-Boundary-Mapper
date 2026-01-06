using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace WTBM.Output
{
    internal static class ConsoleText
    {
        /// <summary>
        /// Ensures a safe printable string (no nulls, no line breaks).
        /// </summary>
        public static string OneLine(string? s)
        {
            if (string.IsNullOrWhiteSpace(s))
                return string.Empty;

            // Normalize newlines for stable table layout.
            s = s.Replace("\r\n", " ").Replace("\n", " ").Replace("\r", " ");
            return s.Trim();
        }

        /// <summary>
        /// Truncates to an exact max width using ASCII ellipsis for stable monospace rendering.
        /// </summary>
        public static string Truncate(string s, int maxWidth)
        {
            s = OneLine(s);

            if (maxWidth <= 0)
                return string.Empty;

            if (s.Length <= maxWidth)
                return s;

            if (maxWidth <= 3)
                return s.Substring(0, maxWidth);

            return s.Substring(0, maxWidth - 3) + "...";
        }

        public static string Safe(object? value)
        {
            if (value is null) return string.Empty;

            return value switch
            {
                string s => OneLine(s),
                IFormattable f => f.ToString(null, CultureInfo.InvariantCulture) ?? string.Empty,
                _ => OneLine(value.ToString())
            };
        }
    }
}

