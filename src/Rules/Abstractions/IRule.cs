using System;
using System.Collections.Generic;
using System.Text;
using WTBM.Core;
using WTBM.Domain.Processes;
using WTBM.Domain.Findings;

namespace WTBM.Rules.Abstractions
{
    internal interface IRule
    {
        string RuleId { get; }
        string Title { get; }
        string Description { get; }
        RuleKind Kind { get; }
        FindingCategory Category { get; }

        IEnumerable<Finding> Evaluate(RuleContext context);
    }

    internal enum RuleKind
    {
        Marker,        // single-entity observation
        Correlation    // multi-entity / boundary
    }
}
