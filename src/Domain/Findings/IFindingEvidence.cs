using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.Findings
{
    internal interface IFindingEvidence
    {
        string Kind { get; }              // stable identifier, e.g. "named-pipe-inventory"
        string Summary { get; }           // one-line, table-friendly
    }
}
