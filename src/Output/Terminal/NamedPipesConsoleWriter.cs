using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using WTBM.Collectors.IPC;
using WTBM.Domain.IPC;

namespace WTBM.Output.Terminal
{
    internal static class NamedPipesConsoleWriter
    {
        /// <summary>
        /// Writes a concise, research-grade summary of named pipes and their
        /// security metadata. This method is intentionally read-only and
        /// performs no analysis or correlation.
        /// </summary>
        public static void WriteSummary(IReadOnlyList<NamedPipeEndpoint> endpoints)
        {
            if (endpoints is null)
                throw new ArgumentNullException(nameof(endpoints));

            Console.WriteLine();
            Console.WriteLine("=== Named Pipes (summary) ===");

            Console.WriteLine(
                "Name                              Path                           Owner                          SD   MIL   DACL  SDDL  Error");
            Console.WriteLine(
                "------------------------------  -----------------------------  -------------------------------  ---  ----  ----  ----  ------------------------------");

            foreach (var ep in endpoints.OrderBy(e => e.Pipe.Name, StringComparer.OrdinalIgnoreCase))
            {
                var pipe = ep.Pipe;
                var sec = ep.Security;

                // Presence flags – intentionally simple and explicit
                var hasSd = sec is not null;
                var hasMil = sec?.MandatoryLabel is not null;
                var hasDacl = sec?.Dacl is not null && sec.Dacl.Count > 0;
                var hasSddl = !string.IsNullOrWhiteSpace(sec?.Sddl);
                var path = !string.IsNullOrWhiteSpace(pipe.Win32Path) ? pipe.Win32Path : pipe.NtPath;
                var owner = string.IsNullOrEmpty(sec?.OwnerName) ? "#" : sec.OwnerName;

                Console.WriteLine(
                    $"{Trim(pipe.Name, 28),-28}  " +
                    $"{Trim(path, 29),-29}  " +
                    $"{Trim(owner, 30),-29}  " +
                    $"{Flag(hasSd),-3}  " +
                    $"{Flag(hasMil),-4}  " +
                    $"{Flag(hasDacl),-4}  " +
                    $"{Flag(hasSddl),-4}  " +
                    $"{Trim(sec?.Error, 30)}");
            }

            Console.WriteLine();
            Console.WriteLine($"Total pipes: {endpoints.Count}");
        }

        // -----------------------------
        // Helpers
        // -----------------------------

        private static string Flag(bool value) => value ? "Y" : "-";

        private static string Trim(string? value, int maxLength)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;

            if (value.Length <= maxLength)
                return value;

            return value.Substring(0, maxLength - 1) + "...";
        }
    }
}
