using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.IPC
{
    internal sealed class NamedPipeSecurityInfo
    {
        public string? OwnerSid { get; init; }
        public string? OwnerName { get; init; }
        public string? Sddl { get; init; }
        public IReadOnlyList<AceInfo>? Dacl { get; init; }
        public MandatoryLabelInfo? MandatoryLabel { get; init; } // parsed from SACL (best-effort)
        public string? Error { get; init; } // reason string
    }
}
