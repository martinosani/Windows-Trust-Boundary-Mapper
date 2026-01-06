using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Output
{
    internal enum ConsoleVerbosity
    {
        Compact = 0,
        Normal = 1,
        Detailed = 2
    }

    internal sealed class ConsoleReportOptions
    {
        public ConsoleVerbosity Verbosity { get; init; } = ConsoleVerbosity.Normal;

        /// <summary>Max rows printed for large tables (null = unlimited).</summary>
        public int? MaxRows { get; init; } = null;

        /// <summary>How many named pipes to preview when a single process finding is requested.</summary>
        public int NamedPipePreviewCount { get; init; } = 10;

        /// <summary>Whether to print an evidence preview when there is a single finding.</summary>
        public bool PrintEvidencePreviewForSingleFinding { get; init; } = true;

        /// <summary>Max rows used to compute auto column widths.</summary>
        public int WidthSampleSize { get; init; } = 200;
    }
}
