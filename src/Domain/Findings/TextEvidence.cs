using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.Findings
{
    /// <summary>
    /// Minimal, general-purpose evidence for findings that are inherently textual
    /// (e.g., privilege lists, engine errors, quick markers).
    /// </summary>
    internal sealed record TextEvidence(string KindValue, string SummaryValue) : IFindingEvidence
    {
        public string Kind => KindValue;
        public string Summary => SummaryValue;
    }
}
