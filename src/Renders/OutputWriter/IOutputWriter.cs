using PTTBM.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace PTTBM.Renders.OutputWriter
{
    /// <summary>
    /// Output abstraction for rendering PTTBM results.
    /// Implementations may write to console, file, JSONL, etc.
    /// </summary>
    internal interface IOutputWriter
    {
        /// <summary>
        /// Writer configuration (formatting, truncation, verbosity, etc.).
        /// </summary>
        OutputOptions Options { get; }

        /// <summary>
        /// Writes a one-line-per-process summary view suitable for triage.
        /// Implementations should not throw on per-item rendering issues; they should degrade gracefully.
        /// </summary>
        void WriteSummary(IEnumerable<ProcessSnapshot> snapshots);
    }

    internal sealed class OutputOptions
    {
        /// <summary>
        /// Maximum width for variable-length columns (e.g., process name, user name).
        /// Null = no truncation.
        /// </summary>
        public int? MaxColumnWidth { get; init; } = 48;

        /// <summary>
        /// If true, include a compact "Flags" column derived from token signals.
        /// </summary>
        public bool IncludeFlags { get; init; } = true;

        /// <summary>
        /// If true, include a trailing "Notes" column (collection errors / warnings).
        /// </summary>
        public bool IncludeNotes { get; init; } = true;

        /// <summary>
        /// Controls the level of detail printed in summary mode.
        /// </summary>
        public SummaryVerbosity Verbosity { get; init; } = SummaryVerbosity.Normal;
    }

    internal enum SummaryVerbosity
    {
        Minimal = 0,
        Normal = 1,
        Verbose = 2
    }

}
