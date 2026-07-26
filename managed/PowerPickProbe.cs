using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace PowerPickProbe
{
    internal static class Program
    {
        private const int OperatorTimeoutMilliseconds = 180 * 1000;
        private const int OperatorOutputCharacters = 256 * 1024;
        private const int OperatorMaximumBytes = 2 * 1024 * 1024;

        // Native BOF only reliably captures stdout (mailslot). Keep all
        // operator-visible text on Console.Out, including errors.
        private static void WriteLineCaptured(string value)
        {
            if (value == null)
            {
                value = String.Empty;
            }
            Console.WriteLine(value);
        }

        private static void WriteBounded(
            string value,
            ref int remainingCharacters,
            ref bool truncationReported,
            int outputLimit)
        {
            if (String.IsNullOrEmpty(value))
            {
                return;
            }

            if (remainingCharacters <= 0)
            {
                if (!truncationReported)
                {
                    WriteLineCaptured(
                        String.Format(
                            "[output truncated at {0} characters]",
                            outputLimit));
                    truncationReported = true;
                }
                return;
            }

            bool truncated = value.Length > remainingCharacters;
            string bounded = truncated
                ? value.Substring(0, remainingCharacters)
                : value;

            WriteLineCaptured(bounded);

            remainingCharacters -= bounded.Length;
            if (truncated && !truncationReported)
            {
                WriteLineCaptured(
                    String.Format(
                        "[output truncated at {0} characters]",
                        outputLimit));
                truncationReported = true;
            }
        }

        private static int InvokeBounded(
            PowerShell powerShell,
            int timeoutMilliseconds,
            int outputCharacters,
            bool surfacePipeline)
        {
            IAsyncResult pending = powerShell.BeginInvoke();
            if (!pending.AsyncWaitHandle.WaitOne(timeoutMilliseconds))
            {
                powerShell.Stop();
                WriteLineCaptured(
                    String.Format(
                        "PowerShell execution exceeded the {0}-second limit.",
                        timeoutMilliseconds / 1000));
                return 124;
            }

            PSDataCollection<PSObject> results = powerShell.EndInvoke(pending);
            int remainingCharacters = outputCharacters;
            bool truncationReported = false;

            if (surfacePipeline)
            {
                foreach (PSObject result in results)
                {
                    if (result != null)
                    {
                        WriteBounded(
                            result.ToString(),
                            ref remainingCharacters,
                            ref truncationReported,
                            outputCharacters);
                    }
                }
            }

            foreach (ErrorRecord error in powerShell.Streams.Error)
            {
                WriteBounded(
                    error.ToString(),
                    ref remainingCharacters,
                    ref truncationReported,
                    outputCharacters);
            }

            return powerShell.Streams.Error.Count > 0 ? 1 : 0;
        }

        private static bool TryDecodeScript(
            string encodedScript,
            int maximumBytes,
            out string scriptText,
            out int byteCount,
            out string error)
        {
            scriptText = null;
            byteCount = 0;
            error = null;

            byte[] scriptBytes;
            try
            {
                scriptBytes = Convert.FromBase64String(encodedScript);
            }
            catch (FormatException)
            {
                error = "The script transport is not valid Base64.";
                return false;
            }

            if (scriptBytes.Length == 0 || scriptBytes.Length > maximumBytes)
            {
                error = String.Format(
                    "The script must be between 1 byte and {0} bytes.",
                    maximumBytes);
                return false;
            }

            scriptText = Encoding.UTF8.GetString(scriptBytes);
            if (scriptText.IndexOf('\0') >= 0)
            {
                error = "The script contains an invalid NUL character.";
                return false;
            }

            byteCount = scriptBytes.Length;
            return true;
        }

        private static int ImportScriptText(
            Runspace runspace,
            string scriptText,
            int timeoutMilliseconds,
            int outputCharacters)
        {
            using (PowerShell powerShell = PowerShell.Create())
            {
                powerShell.Runspace = runspace;
                powerShell.AddScript(scriptText, false);
                // Do not dump import pipeline objects; still surface Error stream.
                return InvokeBounded(
                    powerShell,
                    timeoutMilliseconds,
                    outputCharacters,
                    false);
            }
        }

        private static bool ReadExact(Stream stream, byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count)
            {
                int read = stream.Read(buffer, offset, count - offset);
                if (read <= 0)
                {
                    return false;
                }
                offset += read;
            }
            return true;
        }

        private static List<string> ReadImportsFromMap(string mapName)
        {
            List<string> imports = new List<string>();
            try
            {
                using (MemoryMappedFile map = MemoryMappedFile.OpenExisting(mapName))
                using (MemoryMappedViewStream stream = map.CreateViewStream())
                {
                    byte[] countBytes = new byte[4];
                    if (!ReadExact(stream, countBytes, 4))
                    {
                        return imports;
                    }

                    int count = BitConverter.ToInt32(countBytes, 0);
                    if (count < 0 || count > 32)
                    {
                        WriteLineCaptured("Import map has an invalid count.");
                        return null;
                    }

                    for (int index = 0; index < count; index++)
                    {
                        byte[] lengthBytes = new byte[4];
                        if (!ReadExact(stream, lengthBytes, 4))
                        {
                            WriteLineCaptured("Import map ended early.");
                            return null;
                        }

                        int length = BitConverter.ToInt32(lengthBytes, 0);
                        if (length <= 0 || length > OperatorMaximumBytes)
                        {
                            WriteLineCaptured(
                                String.Format(
                                    "Import map entry {0} has an invalid length.",
                                    index + 1));
                            return null;
                        }

                        byte[] data = new byte[length];
                        if (!ReadExact(stream, data, length))
                        {
                            WriteLineCaptured(
                                String.Format(
                                    "Import map entry {0} could not be read.",
                                    index + 1));
                            return null;
                        }

                        string text = Encoding.UTF8.GetString(data);
                        if (text.IndexOf('\0') >= 0)
                        {
                            WriteLineCaptured(
                                String.Format(
                                    "Session import {0} contains an invalid NUL character.",
                                    index + 1));
                            return null;
                        }

                        imports.Add(text);
                    }
                }
            }
            catch (Exception exception)
            {
                WriteLineCaptured(
                    String.Format(
                        "Failed to open import map '{0}': {1}",
                        mapName,
                        exception.Message));
                return null;
            }

            return imports;
        }

        private static int RunOperatorScriptTexts(
            string commandText,
            List<string> importTexts)
        {
            if (importTexts == null)
            {
                importTexts = new List<string>();
            }

            int totalBytes = Encoding.UTF8.GetByteCount(commandText);
            for (int index = 0; index < importTexts.Count; index++)
            {
                totalBytes += Encoding.UTF8.GetByteCount(importTexts[index]);
                if (totalBytes > OperatorMaximumBytes)
                {
                    WriteLineCaptured(
                        String.Format(
                            "Session imports plus command exceed the {0}-byte limit.",
                            OperatorMaximumBytes));
                    return 2;
                }
            }

            using (Runspace runspace = RunspaceFactory.CreateRunspace())
            {
                runspace.Open();

                for (int index = 0; index < importTexts.Count; index++)
                {
                    int importResult = ImportScriptText(
                        runspace,
                        importTexts[index],
                        OperatorTimeoutMilliseconds,
                        OperatorOutputCharacters);
                    // Timeout is fatal. Non-terminating Error-stream noise from
                    // large modules (e.g. recon scripts) must not abort the run.
                    if (importResult == 124)
                    {
                        WriteLineCaptured(
                            String.Format(
                                "Session import {0} timed out.",
                                index + 1));
                        return importResult;
                    }
                }

                using (PowerShell powerShell = PowerShell.Create())
                {
                    powerShell.Runspace = runspace;
                    powerShell.AddScript(
                        commandText + " | Out-String -Width 4096",
                        false);
                    return InvokeBounded(
                        powerShell,
                        OperatorTimeoutMilliseconds,
                        OperatorOutputCharacters,
                        true);
                }
            }
        }

        private static int RunOperatorScript(
            string encodedCommand,
            string[] encodedImports)
        {
            if (encodedImports == null)
            {
                encodedImports = new string[0];
            }

            List<string> importTexts = new List<string>();

            for (int index = 0; index < encodedImports.Length; index++)
            {
                string importText;
                int importBytes;
                string importError;
                if (!TryDecodeScript(
                        encodedImports[index],
                        OperatorMaximumBytes,
                        out importText,
                        out importBytes,
                        out importError))
                {
                    WriteLineCaptured(
                        String.Format(
                            "Session import {0}: {1}",
                            index + 1,
                            importError));
                    return 2;
                }

                importTexts.Add(importText);
            }

            string commandText;
            int commandBytes;
            string commandError;
            if (!TryDecodeScript(
                    encodedCommand,
                    OperatorMaximumBytes,
                    out commandText,
                    out commandBytes,
                    out commandError))
            {
                WriteLineCaptured(commandError);
                return 2;
            }

            return RunOperatorScriptTexts(commandText, importTexts);
        }

        private static string[] CopyArguments(string[] args, int start)
        {
            string[] result = new string[args.Length - start];
            Array.Copy(args, start, result, 0, result.Length);
            return result;
        }

        private static void RebindConsoleToStdHandles()
        {
            // Native SetStdHandle runs before Main; rebind Console so Out/Error
            // follow the current OS handles (mailslot), not a stale console.
            try
            {
                StreamWriter stdout = new StreamWriter(
                    Console.OpenStandardOutput(),
                    new UTF8Encoding(false))
                {
                    AutoFlush = true
                };
                StreamWriter stderr = new StreamWriter(
                    Console.OpenStandardError(),
                    new UTF8Encoding(false))
                {
                    AutoFlush = true
                };
                Console.SetOut(stdout);
                Console.SetError(stderr);
            }
            catch
            {
            }
        }

        public static int Main(string[] args)
        {
            RebindConsoleToStdHandles();

            try
            {
                if (args == null ||
                    args.Length < 2 ||
                    !String.Equals(args[0], "exec", StringComparison.OrdinalIgnoreCase))
                {
                    WriteLineCaptured(
                        "Usage: PowerPickProbe.exe exec <base64-script> [@@map]");
                    return 2;
                }

                if (args.Length >= 3 &&
                    args[2].StartsWith("@@", StringComparison.Ordinal))
                {
                    List<string> mappedImports = ReadImportsFromMap(args[2].Substring(2));
                    if (mappedImports == null)
                    {
                        return 2;
                    }

                    string commandText;
                    int commandBytes;
                    string commandError;
                    if (!TryDecodeScript(
                            args[1],
                            OperatorMaximumBytes,
                            out commandText,
                            out commandBytes,
                            out commandError))
                    {
                        WriteLineCaptured(commandError);
                        return 2;
                    }

                    return RunOperatorScriptTexts(commandText, mappedImports);
                }

                return RunOperatorScript(args[1], CopyArguments(args, 2));
            }
            catch (Exception exception)
            {
                WriteLineCaptured(
                    String.Format(
                        "PowerShell host failed: {0}: {1}",
                        exception.GetType().FullName,
                        exception.Message));
                return 1;
            }
        }
    }
}
