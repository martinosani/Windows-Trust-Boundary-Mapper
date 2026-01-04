using System;
using System.Collections.Generic;
using System.Text;

namespace WTBM.Domain.Processes
{
    internal sealed class ProcessSnapshot
    {
        public required ProcessRecord Process { get; init; }
        public required TokenInfo Token { get; init; }

    }
}
