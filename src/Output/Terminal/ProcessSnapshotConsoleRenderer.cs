using System;
using System.Linq;
using WTBM.Domain.Processes;

namespace WTBM.Output.Terminal
{
    internal static class ProcessSnapshotConsoleRenderer
    {
        public static void Render(ProcessSnapshot snapshot)
        {
            if (snapshot is null)
                throw new ArgumentNullException(nameof(snapshot));

            RenderProcess(snapshot.Process);
            RenderToken(snapshot.Token);
        }

        private static void RenderProcess(ProcessRecord process)
        {
            WriteHeader("Process");

            WriteKv("PID", process.Pid);
            WriteKv("PPID", process.Ppid);
            WriteKv("Name", process.Name);
            WriteKv("SessionId", process.SessionId);
            WriteKv("ImagePath", process.ImagePath);

            if (!string.IsNullOrWhiteSpace(process.CollectionError))
            {
                WriteWarning($"Process collection error: {process.CollectionError}");
            }

            Console.WriteLine();
        }

        private static void RenderToken(TokenInfo token)
        {
            WriteHeader("Access Token");

            // Identity / Ownership
            WriteSection("Identity / Ownership");
            WriteKv("UserSid", token.UserSid);
            WriteKv("UserName", token.UserName);
            WriteKv("OwnerSid", token.OwnerSid);
            WriteKv("OwnerName", token.OwnerName);
            WriteKv("PrimaryGroupSid", token.PrimaryGroupSid);
            WriteKv("PrimaryGroupName", token.PrimaryGroupName);

            // Core Boundaries
            WriteSection("Core Boundaries / Context");
            WriteKv("IntegrityLevel", token.IntegrityLevel);
            WriteKv("IntegrityRid", token.IntegrityRid);
            WriteKv("SessionId", token.SessionId);
            WriteKv("TokenType", token.TokenType);
            WriteKv("ImpersonationLevel", token.ImpersonationLevel);

            // UAC / Elevation
            WriteSection("UAC / Elevation");
            WriteKv("IsElevated", token.IsElevated);
            WriteKv("ElevationType", token.ElevationType);
            WriteKv("VirtualizationAllowed", token.IsVirtualizationAllowed);
            WriteKv("VirtualizationEnabled", token.IsVirtualizationEnabled);
            WriteKv("UIAccess", token.HasUIAccess);

            // AppContainer
            WriteSection("AppContainer / Sandboxing");
            WriteKv("IsAppContainer", token.IsAppContainer);
            WriteKv("AppContainerSid", token.AppContainerSid);
            WriteKv("AppContainerName", token.AppContainerName);
            WriteList("Capabilities", token.CapabilitiesSids);

            // Groups & Privileges
            WriteSection("Groups / Privileges");
            WriteKv("IsMemberOfAdministrators", token.IsMemberOfAdministrators);
            WriteKv("IsLocalSystem", token.IsLocalSystem);
            WriteKv("IsLocalService", token.IsLocalService);
            WriteKv("IsNetworkService", token.IsNetworkService);

            WriteList(
                "Privileges",
                token.Privileges?.Select(p => $"{p.Name} ({p.Attributes})")
            );

            // Restrictions / Delegation
            WriteSection("Restrictions / Delegation");
            WriteKv("IsRestricted", token.IsRestricted);
            WriteList("RestrictedSids", token.RestrictedSids);
            WriteKv("HasLinkedToken", token.HasLinkedToken);
            WriteKv("LinkedTokenPidHint", token.LinkedTokenPidHint);

            // Provenance
            WriteSection("Provenance");
            WriteKv("AuthenticationId", token.AuthenticationId);
            WriteKv("TokenId", token.TokenId);
            WriteKv("LogonTypeHint", token.LogonTypeHint);

            // Diagnostics
            if (!string.IsNullOrWhiteSpace(token.CollectionError))
            {
                WriteWarning($"Token collection error: {token.CollectionError}");
            }

            Console.WriteLine();
        }

        // =========================
        // Helpers
        // =========================

        private static void WriteHeader(string title)
        {
            Console.WriteLine($"=== {title} ===");
        }

        private static void WriteSection(string title)
        {
            Console.WriteLine();
            Console.WriteLine($"-- {title}");
        }

        private static void WriteKv(string key, object? value)
        {
            Console.WriteLine($"  {key,-28}: {Format(value)}");
        }

        private static void WriteList(string label, System.Collections.Generic.IEnumerable<string>? values)
        {
            if (values == null)
            {
                WriteKv(label, null);
                return;
            }

            var list = values.ToList();
            if (list.Count == 0)
            {
                WriteKv(label, "<empty>");
                return;
            }

            Console.WriteLine($"  {label,-28}:");
            foreach (var v in list)
                Console.WriteLine($"    - {v}");
        }

        private static void WriteWarning(string message)
        {
            var previous = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[!] {message}");
            Console.ForegroundColor = previous;
        }

        private static string Format(object? value)
        {
            return value switch
            {
                null => "<not observable>",
                string s when string.IsNullOrWhiteSpace(s) => "<empty>",
                _ => value.ToString()!
            };
        }
    }
}
