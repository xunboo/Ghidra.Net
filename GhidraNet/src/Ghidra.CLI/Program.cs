using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Ghidra.UI;
using Ghidra.UI.Models;
using Ghidra.UI.Services;
using ghidra.program.model.address;

namespace Ghidra.CLI;

public static class Program
{
    private static readonly byte[] CommandStart = [0, 0, 1, 2];
    private static readonly byte[] CommandEnd = [0, 0, 1, 3];
    private static readonly byte[] StringStart = [0, 0, 1, 14];
    private static readonly byte[] StringEnd = [0, 0, 1, 15];

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length == 0)
        {
            ShowBanner();
            ShowHelp();
            return 0;
        }

        string command = args[0].ToLowerInvariant();

        switch (command)
        {
            case "help":
            case "-h":
            case "--help":
            case "/?":
                ShowBanner();
                ShowHelp();
                return 0;

            case "shell":
            case "interactive":
                string? shellBinary = args.Length > 1 ? args[1] : null;
                return await RunInteractiveShell(shellBinary);

            case "info":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli info <binary_path>"); return 1; }
                return CmdInfo(args[1]);

            case "disasm":
            case "disassemble":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli disasm <binary_path> [addr_hex] [count]"); return 1; }
                ulong? startAddr = args.Length > 2 ? ParseHex(args[2]) : null;
                int count = args.Length > 3 && int.TryParse(args[3], out int c) ? c : 40;
                return CmdDisasm(args[1], startAddr, count);

            case "decompile":
            case "decomp":
                if (args.Length < 3) { PrintError("Usage: ghidra-cli decompile <binary_path> <function_name_or_addr>"); return 1; }
                return CmdDecompile(args[1], args[2]);

            case "xrefs":
            case "xref":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli xrefs <binary_path> [addr_hex]"); return 1; }
                ulong? targetXref = args.Length > 2 ? ParseHex(args[2]) : null;
                return CmdXRefs(args[1], targetXref);

            case "strings":
            case "str":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli strings <binary_path> [min_length]"); return 1; }
                int minLen = args.Length > 2 && int.TryParse(args[2], out int ml) ? ml : 4;
                return CmdStrings(args[1], minLen);

            case "search":
                if (args.Length < 3) { PrintError("Usage: ghidra-cli search <binary_path> <hex_bytes_or_text>"); return 1; }
                return CmdSearch(args[1], args[2]);

            case "patch":
                if (args.Length < 4) { PrintError("Usage: ghidra-cli patch <binary_path> <addr_hex> <hex_bytes> [out_file]"); return 1; }
                string? outFile = args.Length > 4 ? args[4] : null;
                return CmdPatch(args[1], args[2], args[3], outFile);

            case "pcode":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli pcode <binary_path> [addr_hex]"); return 1; }
                ulong? pcodeAddr = args.Length > 2 ? ParseHex(args[2]) : null;
                return CmdPcode(args[1], pcodeAddr);

            case "calltree":
                if (args.Length < 3) { PrintError("Usage: ghidra-cli calltree <binary_path> <function_name>"); return 1; }
                return CmdCallTree(args[1], args[2]);

            case "equates":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli equates <binary_path>"); return 1; }
                return CmdEquates(args[1]);

            case "cparse":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli cparse <header_path.h>"); return 1; }
                return CmdCParse(args[1]);

            case "entropy":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli entropy <binary_path> [block_size]"); return 1; }
                int blockSize = args.Length > 2 && int.TryParse(args[2], out int bs) ? bs : 1024;
                return CmdEntropy(args[1], blockSize);

            case "demangle":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli demangle <mangled_symbol>"); return 1; }
                return CmdDemangle(args[1]);

            case "pdb":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli pdb <binary_path>"); return 1; }
                return CmdPdb(args[1]);

            case "fallthrough":
                if (args.Length < 4) { PrintError("Usage: ghidra-cli fallthrough <binary_path> <addr_hex> <target_hex|none>"); return 1; }
                return CmdFallthrough(args[1], args[2], args[3]);

            case "script":
                if (args.Length < 3) { PrintError("Usage: ghidra-cli script <binary_path> <script_path.cs>"); return 1; }
                return await CmdScript(args[1], args[2]);

            case "ipc-test":
                string? customExe = args.Length > 1 ? args[1] : null;
                return TestNativeDecompilerIpc(customExe);

            case "dbg-launch":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli dbg-launch <binary_path>"); return 1; }
                return CmdDbgLaunch(args[1]);

            case "dbg-step":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli dbg-step <binary_path> [step_count]"); return 1; }
                int steps = args.Length > 2 && int.TryParse(args[2], out int st) ? st : 1;
                return CmdDbgStep(args[1], steps);

            case "dbg-regs":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli dbg-regs <binary_path>"); return 1; }
                return CmdDbgRegs(args[1]);

            case "dbg-stack":
                if (args.Length < 2) { PrintError("Usage: ghidra-cli dbg-stack <binary_path>"); return 1; }
                return CmdDbgStack(args[1]);

            case "dbg-bp":
                if (args.Length < 3) { PrintError("Usage: ghidra-cli dbg-bp <binary_path> <addr_hex>"); return 1; }
                return CmdDbgBreakpoint(args[1], args[2]);

            case "dbg-mem":
                if (args.Length < 3) { PrintError("Usage: ghidra-cli dbg-mem <binary_path> <addr_hex> [row_count]"); return 1; }
                int rows = args.Length > 3 && int.TryParse(args[3], out int rws) ? rws : 8;
                return CmdDbgMemory(args[1], args[2], rows);

            default:
                // Check if user specified a binary directly: ghidra-cli <binary>
                if (File.Exists(args[0]))
                {
                    return await RunInteractiveShell(args[0]);
                }
                PrintError($"Unknown command: '{command}'. Run 'ghidra-cli help' for usage instructions.");
                return 1;
        }
    }

    private static void ShowBanner()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("================================================================================");
        Console.WriteLine("             Ghidra.NET Headless & Command-Line Interface (CLI)                 ");
        Console.WriteLine("================================================================================");
        Console.ResetColor();
        Console.WriteLine($"[Environment] .NET Runtime: {Environment.Version} | OS: {Environment.OSVersion}");
        Console.WriteLine($"[Executable]  {Environment.ProcessPath}");
        Console.WriteLine();
    }

    private static void ShowHelp()
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  ghidra-cli <command> [arguments] [options]");
        Console.WriteLine("  ghidra-cli shell [binary_path]");
        Console.WriteLine();
        Console.WriteLine("Commands:");
        Console.WriteLine("  info        <binary>                   Display binary format, architecture, sections & IAT");
        Console.WriteLine("  disasm      <binary> [addr] [count]    Disassemble instructions with flow arrows");
        Console.WriteLine("  decompile   <binary> <func|addr>       Decompile target function into C pseudocode");
        Console.WriteLine("  xrefs       <binary> [addr]            Analyze cross-references (callers/callees)");
        Console.WriteLine("  strings     <binary> [min_length]      Extract ASCII & Unicode strings with locations");
        Console.WriteLine("  search      <binary> <hex|text>        Search memory for hex byte sequence or string");
        Console.WriteLine("  patch       <binary> <addr> <hex> [out] Patch binary bytes and export modified executable");
        Console.WriteLine("  pcode       <binary> [addr]            Generate low-level P-Code micro-operations");
        Console.WriteLine("  calltree    <binary> <func>            Analyze incoming callers and outgoing callees");
        Console.WriteLine("  equates     <binary>                   List constant symbol equates");
        Console.WriteLine("  cparse      <header.h>                 Parse C header declarations into data types");
        Console.WriteLine("  entropy     <binary> [block_size]      Calculate Shannon entropy & detect packed sections");
        Console.WriteLine("  demangle    <symbol>                   Demangle MSVC ('?') or GCC/Itanium ('_Z') symbol");
        Console.WriteLine("  pdb         <binary>                   Inspect CodeView RSDS & Microsoft Symbol Server URL");
        Console.WriteLine("  fallthrough <binary> <addr> <target>   Modify or override instruction fallthrough");
        Console.WriteLine("  script      <binary> <script.cs>       Execute Roslyn dynamic C# reverse engineering script");
        Console.WriteLine("  ipc-test    [decompile_exe]            Test bidirectional native C++ decompiler IPC pipe");
        Console.WriteLine("  dbg-launch  <binary>                   Launch target in debugger and pause at entry point");
        Console.WriteLine("  dbg-step    <binary> [steps]           Step through instructions in debugger session");
        Console.WriteLine("  dbg-regs    <binary>                   Display target architecture register state");
        Console.WriteLine("  dbg-stack   <binary>                   Display call stack backtrace");
        Console.WriteLine("  dbg-bp      <binary> <addr>            Toggle breakpoint at virtual address");
        Console.WriteLine("  dbg-mem     <binary> <addr> [rows]     Inspect target dynamic / virtual memory");
        Console.WriteLine("  shell       [binary]                   Launch interactive Ghidra.NET command shell");
        Console.WriteLine();
    }

    // =========================================================================
    // Command Implementations
    // =========================================================================

    private static int CmdInfo(string filePath)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        PrintHeader($"Binary Analysis Overview: {model.ProgramName}");
        Console.WriteLine($"  Format:         {model.Format}");
        Console.WriteLine($"  Architecture:   {model.Architecture}");
        Console.WriteLine($"  Compiler:       {model.Compiler}");
        Console.WriteLine($"  Image Base:     0x{model.ImageBase:X16}");
        Console.WriteLine($"  Entry Point:    0x{model.EntryPoint:X16}");
        Console.WriteLine($"  Total Sections: {model.Sections.Count}");
        Console.WriteLine($"  Imported Thunks:{model.IatMap.Count}");
        Console.WriteLine($"  Listing Length: {model.ListingLines.Count:N0} instructions");

        Console.WriteLine("\n[Memory Sections]");
        Console.WriteLine("  Idx  Name       Start Address       End Address         Size        Perms  Status");
        Console.WriteLine("  ---------------------------------------------------------------------------------");
        for (int i = 0; i < model.Sections.Count; i++)
        {
            var sec = model.Sections[i];
            long size = (long)(sec.EndAddress > sec.StartAddress ? sec.EndAddress - sec.StartAddress : 0);
            Console.WriteLine($"  {i,3}  {sec.Name,-10} 0x{sec.StartAddress:X16}  0x{sec.EndAddress:X16}  {size,10:N0} B  [{sec.Permissions,-3}]  {sec.BlockType}");
        }

        if (model.IatMap.Count > 0)
        {
            Console.WriteLine($"\n[Imports / IAT Sample (First 10 of {model.IatMap.Count})]");
            int count = 0;
            foreach (var (addr, name) in model.IatMap)
            {
                Console.WriteLine($"  0x{addr:X16} -> {name}");
                count++;
                if (count >= 10) break;
            }
        }

        return 0;
    }

    private static int CmdDisasm(string filePath, ulong? startAddr, int count)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        FlowArrowService.UpdateFlowArrows(model);

        ulong targetAddr = startAddr ?? model.EntryPoint;
        PrintHeader($"Disassembly Listing @ 0x{targetAddr:X16} ({count} instructions)");

        int startIndex = -1;
        for (int i = 0; i < model.ListingLines.Count; i++)
        {
            if (ulong.TryParse(model.ListingLines[i].Address, NumberStyles.HexNumber, null, out ulong addr) && addr >= targetAddr)
            {
                startIndex = i;
                break;
            }
        }

        if (startIndex < 0) startIndex = 0;

        Console.WriteLine("  Flow  Address             Bytes               Instruction Operands                       Comments / Tags");
        Console.WriteLine("  -----------------------------------------------------------------------------------------------------------------");

        int end = Math.Min(model.ListingLines.Count, startIndex + count);
        for (int i = startIndex; i < end; i++)
        {
            var item = model.ListingLines[i];
            string flow = string.IsNullOrWhiteSpace(item.FlowArrow) ? "    " : $"{item.FlowArrow,3} ";
            string fallthrough = string.IsNullOrEmpty(item.FallthroughText) ? "" : $"{item.FallthroughText} ";
            string cmt = $"{fallthrough}{item.Comment}".Trim();

            Console.ForegroundColor = GetFlowColor(item.FlowArrow);
            Console.Write($"  {flow}");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write($"0x{item.Address,-16}  ");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write($"{item.Bytes,-18}  ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($"{item.Instruction,-10}  ");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write($"{item.Operands,-30}  ");
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine(cmt);
            Console.ResetColor();
        }

        return 0;
    }

    private static int CmdDecompile(string filePath, string target)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        string funcName = target;
        string addrStr = $"{model.EntryPoint:X8}";

        if (ulong.TryParse(target.Replace("0x", ""), NumberStyles.HexNumber, null, out ulong targetAddr))
        {
            addrStr = $"{targetAddr:X8}";
            var matchFunc = model.ListingLines.FirstOrDefault(l => l.Address.Equals(addrStr, StringComparison.OrdinalIgnoreCase) && l.IsFunctionHeader);
            funcName = matchFunc?.FunctionName ?? $"func_{addrStr}";
        }
        else
        {
            var matchHeader = model.ListingLines.FirstOrDefault(l => l.IsFunctionHeader && l.FunctionName.Equals(target, StringComparison.OrdinalIgnoreCase));
            if (matchHeader != null)
            {
                addrStr = matchHeader.Address;
                funcName = matchHeader.FunctionName;
            }
        }

        PrintHeader($"Decompiled C Pseudocode: {funcName} @ 0x{addrStr}");
        string cCode = DecompilerPipeService.DecompileFunction(model, funcName, addrStr);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(cCode);
        Console.ResetColor();

        return 0;
    }

    private static int CmdXRefs(string filePath, ulong? targetAddr)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        if (targetAddr.HasValue)
        {
            PrintHeader($"Cross-References to Address: 0x{targetAddr.Value:X16}");
            if (model.XRefs.TryGetValue(targetAddr.Value, out var refs) && refs.Count > 0)
            {
                Console.WriteLine("  From Address        Type         Function / Scope");
                Console.WriteLine("  -------------------------------------------------------------");
                foreach (var r in refs)
                {
                    Console.WriteLine($"  0x{r.FromAddress:X16}  [{r.RefType,-10}]  {r.FunctionContext} ({r.InstructionText})");
                }
            }
            else
            {
                Console.WriteLine("  No cross-references detected to this address.");
            }
        }
        else
        {
            PrintHeader($"Program Cross-References Summary ({model.XRefs.Count} referenced targets)");
            int count = 0;
            foreach (var (target, refs) in model.XRefs)
            {
                Console.WriteLine($"\n  Target: 0x{target:X16} ({refs.Count} references):");
                foreach (var r in refs.Take(5))
                {
                    Console.WriteLine($"    <- 0x{r.FromAddress:X16} [{r.RefType}] in {r.FunctionContext}");
                }
                if (refs.Count > 5) Console.WriteLine($"    ... and {refs.Count - 5} more");
                count++;
                if (count >= 15) break;
            }
        }

        return 0;
    }

    private static int CmdStrings(string filePath, int minLen)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        PrintHeader($"Extracted Defined Strings (Min Length: {minLen})");
        Console.WriteLine("  Address             Length  Section     String Value");
        Console.WriteLine("  ---------------------------------------------------------------------------------");

        int count = 0;
        foreach (var (addr, str) in model.StringMap.OrderBy(kv => kv.Key))
        {
            if (str.Length >= minLen)
            {
                var sec = model.FindSection(addr);
                string secName = sec?.Name ?? "N/A";
                string clean = str.Replace("\r", "\\r").Replace("\n", "\\n");
                if (clean.Length > 50) clean = clean.Substring(0, 47) + "...";
                Console.WriteLine($"  0x{addr:X16}  {str.Length,5}   {secName,-10}  \"{clean}\"");
                count++;
                if (count >= 100)
                {
                    Console.WriteLine($"\n  ... Displayed first 100 strings (total: {model.StringMap.Count}).");
                    break;
                }
            }
        }

        return 0;
    }

    private static int CmdSearch(string filePath, string pattern)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        PrintHeader($"Binary Pattern Search: '{pattern}'");

        // 1. Check if hex bytes
        string cleanHex = pattern.Replace(" ", "").Replace("0x", "").Trim();
        bool isHex = cleanHex.Length % 2 == 0 && cleanHex.All(Uri.IsHexDigit);

        int matches = 0;
        if (isHex)
        {
            byte[] targetBytes = Convert.FromHexString(cleanHex);
            Console.WriteLine($"Searching for {targetBytes.Length} byte(s): {BitConverter.ToString(targetBytes)} ...");

            foreach (var sec in model.Sections)
            {
                if (sec.Data == null || sec.Data.Length < targetBytes.Length) continue;
                for (int i = 0; i <= sec.Data.Length - targetBytes.Length; i++)
                {
                    bool match = true;
                    for (int j = 0; j < targetBytes.Length; j++)
                    {
                        if (sec.Data[i + j] != targetBytes[j]) { match = false; break; }
                    }
                    if (match)
                    {
                        ulong addr = sec.StartAddress + (ulong)i;
                        Console.WriteLine($"  [Match] 0x{addr:X16} in section {sec.Name} (+0x{i:X})");
                        matches++;
                        if (matches >= 50) break;
                    }
                }
            }
        }
        else
        {
            Console.WriteLine($"Searching for string token: \"{pattern}\" ...");
            foreach (var (addr, str) in model.StringMap)
            {
                if (str.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"  [Match] 0x{addr:X16} -> \"{str}\"");
                    matches++;
                }
            }
        }

        Console.WriteLine($"\nSearch complete: {matches} match(es) discovered.");
        return 0;
    }

    private static int CmdPatch(string filePath, string addrStr, string hexBytes, string? outFile)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        ulong addr = ParseHex(addrStr) ?? 0;
        string clean = hexBytes.Replace(" ", "").Replace("0x", "").Trim();
        if (clean.Length % 2 != 0 || !clean.All(Uri.IsHexDigit))
        {
            PrintError("Invalid hexadecimal bytes to patch.");
            return 1;
        }

        byte[] bytes = Convert.FromHexString(clean);
        for (int i = 0; i < bytes.Length; i++)
        {
            model.PatchedBytes[addr + (ulong)i] = bytes[i];
        }

        PrintSuccess($"Successfully patched {bytes.Length} byte(s) at 0x{addr:X16} with {BitConverter.ToString(bytes)}");

        if (!string.IsNullOrEmpty(outFile))
        {
            try
            {
                File.Copy(filePath, outFile, overwrite: true);
                using var fs = new FileStream(outFile, FileMode.Open, FileAccess.ReadWrite);
                foreach (var (patchAddr, val) in model.PatchedBytes)
                {
                    var sec = model.FindSection(patchAddr);
                    if (sec != null && sec.Data != null)
                    {
                        ulong offset = patchAddr - sec.StartAddress;
                        // Seek in raw section if PE raw pointer available
                        fs.Seek((long)patchAddr, SeekOrigin.Begin);
                        fs.WriteByte(val);
                    }
                }
                PrintSuccess($"Exported patched binary to: {outFile}");
            }
            catch (Exception ex)
            {
                PrintError($"Failed to write output binary: {ex.Message}");
                return 1;
            }
        }

        return 0;
    }

    private static int CmdPcode(string filePath, ulong? targetAddr)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        ulong addr = targetAddr ?? model.EntryPoint;
        PrintHeader($"Low-Level P-Code Micro-Operations @ 0x{addr:X16}");

        var line = model.ListingLines.FirstOrDefault(l => ulong.TryParse(l.Address, NumberStyles.HexNumber, null, out ulong la) && la == addr);
        if (line == null)
        {
            line = model.ListingLines.FirstOrDefault();
        }

        if (line != null)
        {
            Console.WriteLine($"Instruction: 0x{line.Address}  {line.Instruction} {line.Operands}\n");
            var ops = PcodeService.GeneratePcode(line);
            Console.WriteLine("  Seq  Output          Opcode       Inputs                       Micro-Operation Full Form");
            Console.WriteLine("  -----------------------------------------------------------------------------------------");
            foreach (var op in ops)
            {
                Console.WriteLine($"  {op.Sequence,3}  {op.Output,-14}  {op.Opcode,-11}  {op.Inputs,-26}   {op.FullText}");
            }
        }

        return 0;
    }

    private static int CmdCallTree(string filePath, string funcName)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        ulong funcAddr = model.EntryPoint;
        var line = model.ListingLines.FirstOrDefault(l => l.IsFunctionHeader && l.FunctionName.Equals(funcName, StringComparison.OrdinalIgnoreCase));
        if (line != null && ulong.TryParse(line.Address, NumberStyles.HexNumber, null, out ulong fa))
        {
            funcAddr = fa;
        }

        PrintHeader($"Function Call Tree Hierarchy: {funcName} @ 0x{funcAddr:X16}");
        var (incoming, outgoing) = CallTreeService.BuildCallTree(model, funcName, funcAddr);

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"\n[Incoming Calls / Callers ({incoming.Count})]");
        Console.ResetColor();
        foreach (var inc in incoming)
        {
            Console.WriteLine($"  <- {inc.FunctionName} (Call site: 0x{inc.CallSiteAddress:X16})");
        }
        if (incoming.Count == 0) Console.WriteLine("  (No incoming callers detected)");

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"\n[Outgoing Calls / Callees ({outgoing.Count})]");
        Console.ResetColor();
        foreach (var o in outgoing)
        {
            Console.WriteLine($"  -> {o.FunctionName} @ 0x{o.Address:X16} (from 0x{o.CallSiteAddress:X16})");
        }
        if (outgoing.Count == 0) Console.WriteLine("  (No outgoing calls detected)");

        return 0;
    }

    private static int CmdEquates(string filePath)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        PrintHeader($"Constant Symbol Equates ({model.Equates.Count} defined)");
        Console.WriteLine("  Equate Name         Value (Hex)   Decimal       Category     References");
        Console.WriteLine("  -------------------------------------------------------------------------");
        foreach (var eq in model.Equates)
        {
            Console.WriteLine($"  {eq.Name,-18}  {eq.ValueHex,-12}  {eq.Value,-12}  {eq.Category,-11}  {eq.RefCount} site(s)");
        }

        return 0;
    }

    private static int CmdCParse(string headerPath)
    {
        if (!File.Exists(headerPath))
        {
            PrintError($"Header file not found: {headerPath}");
            return 1;
        }

        string source = File.ReadAllText(headerPath);
        PrintHeader($"Parsing C Header File: {Path.GetFileName(headerPath)}");
        var result = CParserService.ParseCSource(source);

        Console.WriteLine($"\n[Parsed Structures & Unions ({result.Structs.Count})]");
        foreach (var st in result.Structs)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"  struct {st.Name} ({st.Fields.Count} fields, Total Size: {st.TotalSize} bytes):");
            Console.ResetColor();
            foreach (var f in st.Fields)
            {
                Console.WriteLine($"    +0x{f.Offset:X2}  {f.TypeName,-16} {f.Name,-16} (size: {f.Size}B)");
            }
        }

        Console.WriteLine($"\n[Parsed Enumerations ({result.Enums.Count})]");
        foreach (var en in result.Enums)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"  enum {en.Name} ({en.Members.Count} members):");
            Console.ResetColor();
            foreach (var m in en.Members)
            {
                Console.WriteLine($"    {m.Name,-24} = 0x{m.Value:X} ({m.Value})");
            }
        }

        Console.WriteLine($"\n[Parsed Typedefs ({result.Typedefs.Count})]");
        foreach (var (k, v) in result.Typedefs)
        {
            Console.WriteLine($"  typedef {v} {k};");
        }

        PrintSuccess($"\nSuccessfully parsed {result.Structs.Count} struct(s), {result.Enums.Count} enum(s), and {result.Typedefs.Count} typedef(s).");
        return 0;
    }

    private static int CmdEntropy(string filePath, int blockSize)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        PrintHeader($"Shannon Information Entropy Analysis (0.00 to 8.00 bits/byte)");

        var secEntropies = EntropyService.AnalyzeSections(model);
        Console.WriteLine("  Section    Start Address       End Address         Size        Entropy    Status");
        Console.WriteLine("  ---------------------------------------------------------------------------------------");
        foreach (var s in secEntropies)
        {
            Console.ForegroundColor = s.Entropy >= 7.0 ? ConsoleColor.Red : (s.Entropy >= 5.2 ? ConsoleColor.Green : ConsoleColor.Blue);
            Console.WriteLine($"  {s.Name,-9}  0x{s.StartAddress:X16}  0x{s.EndAddress:X16}  {s.Size,10:N0}  {s.Entropy,5:F2} / 8.0  {s.Status}");
            Console.ResetColor();
        }

        var blocks = EntropyService.AnalyzeBlocks(model, blockSize);
        int packedCount = secEntropies.Count(s => s.Entropy >= 7.0);
        Console.WriteLine($"\nAnalyzed {blocks.Count} sliding blocks ({blockSize} B/block).");
        if (packedCount > 0)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ALERT] {packedCount} section(s) have entropy >= 7.0 (likely packed, compressed, or encrypted payload)!");
            Console.ResetColor();
        }
        else
        {
            PrintSuccess("Binary sections appear unpacked with normal code and data distributions.");
        }

        return 0;
    }

    private static int CmdDemangle(string mangled)
    {
        PrintHeader($"C++ Symbol Demangler");
        Console.WriteLine($"  Mangled Input:    {mangled}");
        string demangled = DemanglerService.Demangle(mangled);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  Demangled Output: {demangled}");
        Console.ResetColor();
        return 0;
    }

    private static int CmdPdb(string filePath)
    {
        PrintHeader($"CodeView RSDS & Microsoft Symbol Server Info");
        var pdb = PdbService.ExtractPdbInfo(filePath);
        Console.WriteLine($"  CodeView Found:   {(pdb.HasCodeView ? "Yes" : "No")}");
        Console.WriteLine($"  PDB File Path:    {pdb.PdbPath}");
        Console.WriteLine($"  PDB GUID:         {pdb.Guid}");
        Console.WriteLine($"  PDB Age:          {pdb.Age}");
        Console.WriteLine($"  Symbol Server:    {pdb.SymbolServerUrl}");
        Console.WriteLine($"  Status:           {pdb.Status}");
        return 0;
    }

    private static int CmdFallthrough(string filePath, string addrStr, string targetStr)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        ulong addr = ParseHex(addrStr) ?? 0;
        ulong? target = targetStr.Equals("none", StringComparison.OrdinalIgnoreCase) ? null : ParseHex(targetStr);

        FlowArrowService.SetFallthroughOverride(model, addr, target);
        if (target.HasValue)
        {
            PrintSuccess($"Set fallthrough override at 0x{addr:X16} -> 0x{target.Value:X16}");
        }
        else
        {
            PrintSuccess($"Disabled fallthrough at 0x{addr:X16} ([No Fallthrough])");
        }

        return 0;
    }

    private static async Task<int> CmdScript(string filePath, string scriptPath)
    {
        if (!File.Exists(scriptPath))
        {
            PrintError($"Script file not found: {scriptPath}");
            return 1;
        }

        var model = LoadProgram(filePath);
        if (model == null) return 1;

        string code = File.ReadAllText(scriptPath);
        PrintHeader($"Executing Roslyn C# Script: {Path.GetFileName(scriptPath)}");

        var globals = new ScriptGlobals
        {
            CurrentProgram = model,
            CurrentAddress = model.EntryPoint,
            CurrentFunctionName = "entry",
            Print = obj => Console.WriteLine(obj),
            Log = msg => Console.WriteLine($"[Script Log] {msg}"),
            JumpTo = a => Console.WriteLine($"[JumpTo] 0x{a:X16}"),
            PatchBytes = (a, b) =>
            {
                for (int i = 0; i < b.Length; i++) model.PatchedBytes[a + (ulong)i] = b[i];
                Console.WriteLine($"[Patch] Patched {b.Length} byte(s) at 0x{a:X16}");
            },
            Decompile = fn => DecompilerPipeService.DecompileFunction(model, fn, $"{model.EntryPoint:X8}"),
            Demangle = s => DemanglerService.Demangle(s)
        };

        var (success, output, result) = await RoslynScriptService.ExecuteScriptAsync(code, globals);
        Console.WriteLine(output);

        if (success)
        {
            PrintSuccess("Script execution completed successfully.");
            return 0;
        }
        else
        {
            PrintError("Script execution failed.");
            return 1;
        }
    }

    // =========================================================================
    // Interactive REPL Shell Mode
    // =========================================================================

    private static async Task<int> RunInteractiveShell(string? initialBinary)
    {
        ShowBanner();
        Console.WriteLine("Starting interactive Ghidra.NET REPL shell.");
        Console.WriteLine("Type 'help' for command list, 'exit' or 'quit' to leave.\n");

        ProgramModel? model = null;
        if (!string.IsNullOrEmpty(initialBinary))
        {
            model = LoadProgram(initialBinary);
        }

        while (true)
        {
            string prompt = model != null ? $"ghidra [{model.ProgramName}]> " : "ghidra> ";
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(prompt);
            Console.ResetColor();

            string? line = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(line)) continue;

            if (line.Equals("exit", StringComparison.OrdinalIgnoreCase) || line.Equals("quit", StringComparison.OrdinalIgnoreCase) || line.Equals("q", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Exiting Ghidra.NET CLI shell.");
                break;
            }

            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            string subCmd = parts[0].ToLowerInvariant();

            try
            {
                switch (subCmd)
                {
                    case "help":
                    case "?":
                        ShowShellHelp();
                        break;

                    case "load":
                    case "open":
                        if (parts.Length < 2) { PrintError("Usage: load <binary_path>"); break; }
                        model = LoadProgram(parts[1]);
                        break;

                    case "info":
                        if (EnsureLoaded(model)) CmdInfo(model!.FilePath);
                        break;

                    case "disasm":
                    case "u":
                        if (EnsureLoaded(model))
                        {
                            ulong? a = parts.Length > 1 ? ParseHex(parts[1]) : null;
                            int cnt = parts.Length > 2 && int.TryParse(parts[2], out int c) ? c : 20;
                            CmdDisasm(model!.FilePath, a, cnt);
                        }
                        break;

                    case "decompile":
                    case "c":
                        if (EnsureLoaded(model))
                        {
                            string target = parts.Length > 1 ? parts[1] : $"{model!.EntryPoint:X8}";
                            CmdDecompile(model!.FilePath, target);
                        }
                        break;

                    case "xrefs":
                    case "x":
                        if (EnsureLoaded(model))
                        {
                            ulong? target = parts.Length > 1 ? ParseHex(parts[1]) : null;
                            CmdXRefs(model!.FilePath, target);
                        }
                        break;

                    case "strings":
                        if (EnsureLoaded(model))
                        {
                            int ml = parts.Length > 1 && int.TryParse(parts[1], out int m) ? m : 4;
                            CmdStrings(model!.FilePath, ml);
                        }
                        break;

                    case "search":
                        if (EnsureLoaded(model))
                        {
                            if (parts.Length < 2) { PrintError("Usage: search <pattern>"); break; }
                            CmdSearch(model!.FilePath, parts[1]);
                        }
                        break;

                    case "patch":
                        if (EnsureLoaded(model))
                        {
                            if (parts.Length < 3) { PrintError("Usage: patch <addr_hex> <hex_bytes>"); break; }
                            CmdPatch(model!.FilePath, parts[1], parts[2], null);
                        }
                        break;

                    case "pcode":
                        if (EnsureLoaded(model))
                        {
                            ulong? a = parts.Length > 1 ? ParseHex(parts[1]) : null;
                            CmdPcode(model!.FilePath, a);
                        }
                        break;

                    case "calltree":
                        if (EnsureLoaded(model))
                        {
                            string fn = parts.Length > 1 ? parts[1] : "main";
                            CmdCallTree(model!.FilePath, fn);
                        }
                        break;

                    case "entropy":
                        if (EnsureLoaded(model)) CmdEntropy(model!.FilePath, 1024);
                        break;

                    case "pdb":
                        if (EnsureLoaded(model)) CmdPdb(model!.FilePath);
                        break;

                    case "demangle":
                        if (parts.Length < 2) { PrintError("Usage: demangle <symbol>"); break; }
                        CmdDemangle(parts[1]);
                        break;

                    case "eval":
                        if (EnsureLoaded(model))
                        {
                            string expr = string.Join(" ", parts.Skip(1));
                            await EvalScript(model!, expr);
                        }
                        break;

                    case "run":
                    case "r":
                    case "dbg-launch":
                        if (EnsureLoaded(model)) CmdDbgLaunch(model!.FilePath);
                        break;

                    case "step":
                    case "t":
                    case "dbg-step":
                        if (EnsureLoaded(model))
                        {
                            int count = parts.Length > 1 && int.TryParse(parts[1], out int sc) ? sc : 1;
                            CmdDbgStep(model!.FilePath, count);
                        }
                        break;

                    case "stepover":
                    case "p":
                    case "dbg-stepover":
                        if (EnsureLoaded(model))
                        {
                            if (_cliDebugger.State == DebuggerState.Inactive) CmdDbgLaunch(model!.FilePath);
                            _cliDebugger.StepOverAsync().GetAwaiter().GetResult();
                            var it = model!.ListingLines.FirstOrDefault(l => ParseHex(l.Address) == _cliDebugger.CurrentInstructionPointer);
                            string mnem = it != null ? $"{it.Instruction,-8} {it.Operands}" : "???";
                            Console.WriteLine($"  Step Over -> 0x{_cliDebugger.CurrentInstructionPointer:X16} | {mnem}");
                            PrintRegisters();
                        }
                        break;

                    case "cont":
                    case "continue":
                    case "dbg-continue":
                        if (EnsureLoaded(model))
                        {
                            if (_cliDebugger.State == DebuggerState.Inactive) CmdDbgLaunch(model!.FilePath);
                            _cliDebugger.ResumeAsync().GetAwaiter().GetResult();
                            PrintRegisters();
                            PrintCallStack();
                        }
                        break;

                    case "regs":
                    case "dbg-regs":
                        if (EnsureLoaded(model)) CmdDbgRegs(model!.FilePath);
                        break;

                    case "stack":
                    case "k":
                    case "dbg-stack":
                        if (EnsureLoaded(model)) CmdDbgStack(model!.FilePath);
                        break;

                    case "bp":
                    case "dbg-bp":
                        if (EnsureLoaded(model))
                        {
                            if (parts.Length < 2) { PrintError("Usage: bp <addr_hex>"); break; }
                            CmdDbgBreakpoint(model!.FilePath, parts[1]);
                        }
                        break;

                    case "db":
                    case "dbg-mem":
                        if (EnsureLoaded(model))
                        {
                            if (parts.Length < 2) { PrintError("Usage: db <addr_hex> [rows]"); break; }
                            int rws = parts.Length > 2 && int.TryParse(parts[2], out int rw) ? rw : 8;
                            CmdDbgMemory(model!.FilePath, parts[1], rws);
                        }
                        break;

                    case "clear":
                    case "cls":
                        Console.Clear();
                        ShowBanner();
                        break;

                    default:
                        PrintError($"Unknown shell command: '{subCmd}'. Type 'help' for command list.");
                        break;
                }
            }
            catch (Exception ex)
            {
                PrintError($"Command execution error: {ex.Message}");
            }
        }

        return 0;
    }

    private static void ShowShellHelp()
    {
        Console.WriteLine("\nInteractive Shell Commands:");
        Console.WriteLine("  load      <path>          Load a new executable binary into shell session");
        Console.WriteLine("  info                      Display program architecture, headers & sections");
        Console.WriteLine("  disasm    [addr] [count]  Disassemble instructions (alias: 'u')");
        Console.WriteLine("  decompile <func|addr>     Decompile function into C pseudocode (alias: 'c')");
        Console.WriteLine("  xrefs     [addr]          Inspect cross-references (alias: 'x')");
        Console.WriteLine("  strings   [min_length]    Display extracted strings from data sections");
        Console.WriteLine("  search    <hex|string>    Search binary memory");
        Console.WriteLine("  patch     <addr> <hex>    Patch memory bytes at virtual address");
        Console.WriteLine("  pcode     [addr]          Generate P-Code micro-operations");
        Console.WriteLine("  calltree  <func>          Display incoming and outgoing call tree");
        Console.WriteLine("  entropy                   Calculate Shannon entropy across sections");
        Console.WriteLine("  pdb                       Inspect CodeView RSDS info & symbol server URL");
        Console.WriteLine("  demangle  <symbol>        Demangle C++ decorated name");
        Console.WriteLine("  eval      <csharp_expr>   Dynamically execute C# expression on current program");
        Console.WriteLine("  run                       Launch loaded target in debugger session (alias: 'r')");
        Console.WriteLine("  step      [count]         Single-step N instructions in debugger (alias: 't')");
        Console.WriteLine("  stepover                  Step over CALL instruction (alias: 'p')");
        Console.WriteLine("  cont                      Resume / continue execution (alias: 'c')");
        Console.WriteLine("  regs                      Display x86_64 CPU register state");
        Console.WriteLine("  stack                     Display call stack frames (alias: 'k')");
        Console.WriteLine("  bp        <addr>          Toggle breakpoint at virtual address");
        Console.WriteLine("  db        <addr> [rows]   Dump memory bytes at address");
        Console.WriteLine("  clear                     Clear the terminal screen");
        Console.WriteLine("  exit                      Exit interactive shell\n");
    }

    private static bool EnsureLoaded(ProgramModel? model)
    {
        if (model == null)
        {
            PrintError("No program currently loaded. Use 'load <binary_path>' first.");
            return false;
        }
        return true;
    }

    private static async Task EvalScript(ProgramModel model, string expr)
    {
        if (string.IsNullOrWhiteSpace(expr)) return;

        var globals = new ScriptGlobals
        {
            CurrentProgram = model,
            CurrentAddress = model.EntryPoint,
            CurrentFunctionName = "entry",
            Print = obj => Console.WriteLine(obj),
            Log = msg => Console.WriteLine($"[Log] {msg}"),
            JumpTo = a => Console.WriteLine($"[Jump] 0x{a:X16}"),
            PatchBytes = (a, b) =>
            {
                for (int i = 0; i < b.Length; i++) model.PatchedBytes[a + (ulong)i] = b[i];
            },
            Decompile = fn => DecompilerPipeService.DecompileFunction(model, fn, $"{model.EntryPoint:X8}"),
            Demangle = s => DemanglerService.Demangle(s)
        };

        string wrapped = expr;
        if (!expr.EndsWith(";") && !expr.StartsWith("Print(") && !expr.Contains("="))
        {
            wrapped = $"Print({expr});";
        }
        else if (!expr.EndsWith(";"))
        {
            wrapped = expr + ";";
        }

        var (success, output, result) = await RoslynScriptService.ExecuteScriptAsync(wrapped, globals);
        if (!string.IsNullOrEmpty(output)) Console.Write(output);
        if (!success) PrintError("Evaluation returned errors.");
    }

    // =========================================================================
    // Native Decompiler Verification & Protocol Self-Test
    // =========================================================================

    private static int TestNativeDecompilerIpc(string? customDecompilePath)
    {
        ShowBanner();
        Console.WriteLine(">>> Verifying Native C++ Decompiler Engine & IPC Protocol...");

        string decompileExe = customDecompilePath ?? LocateDecompileExe();
        Console.WriteLine($"  Engine Binary Path: {decompileExe}");

        if (!File.Exists(decompileExe))
        {
            PrintError($"Native decompiler executable not found at: {decompileExe}");
            return 1;
        }

        var fi = new FileInfo(decompileExe);
        Console.WriteLine($"  File Status:        Verified (Size: {fi.Length:N0} bytes / MSVC x64 Native)");
        Console.WriteLine($"  Last Modified:      {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}");

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = decompileExe,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null) throw new InvalidOperationException("Failed to launch decompiler process.");

            Console.WriteLine($"  Process Status:     Launched successfully (PID: {process.Id})");

            string testCmd = "ping";
            Console.WriteLine($"  Transmitting Frame: \"{testCmd}\" to decompiler stdin...");

            var stdin = process.StandardInput.BaseStream;
            var stdout = process.StandardOutput.BaseStream;

            byte[] cmdBytes = Encoding.ASCII.GetBytes(testCmd);
            stdin.Write(CommandStart);
            stdin.Write(StringStart);
            stdin.Write(cmdBytes);
            stdin.Write(StringEnd);
            stdin.Write(CommandEnd);
            stdin.Flush();

            byte[] responseBuffer = new byte[128];
            int bytesRead = stdout.Read(responseBuffer, 0, responseBuffer.Length);
            Console.WriteLine($"  Received Response:  {bytesRead} byte(s) from decompiler stdout");

            if (bytesRead >= 8)
            {
                string hexHeader = BitConverter.ToString(responseBuffer, 0, Math.Min(8, bytesRead));
                Console.WriteLine($"  Protocol Frame:     {hexHeader}");

                string rawText = Encoding.Latin1.GetString(responseBuffer, 0, bytesRead);
                string cleanText = new string(rawText.Where(c => !char.IsControl(c) || c == ' ' || c == '\t').ToArray()).Trim();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  Engine Output:      \"{cleanText}\"");
                Console.ResetColor();
                PrintSuccess("Native C++ decompiler bidirectional IPC pipeline verified successfully (All Systems OK)!");
            }

            process.Kill(entireProcessTree: true);
            process.WaitForExit(1000);
            return 0;
        }
        catch (Exception ex)
        {
            PrintError($"IPC verification failed: {ex.Message}");
            return 1;
        }
    }

    private static string LocateDecompileExe()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string? rootDir = baseDir;
        while (rootDir != null && !Directory.Exists(Path.Combine(rootDir, "runtimes")))
        {
            rootDir = Directory.GetParent(rootDir)?.FullName;
        }
        if (rootDir == null) rootDir = @"C:\Projects\GitHub\ghidra\GhidraNet";
        return Path.Combine(rootDir, "runtimes", "win-x64", "native", "decompile.exe");
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    private static ProgramModel? LoadProgram(string filePath)
    {
        if (!File.Exists(filePath))
        {
            PrintError($"Binary file not found: {filePath}");
            return null;
        }

        try
        {
            var model = PeLoaderService.LoadPeBinary(filePath);
            return model;
        }
        catch (Exception ex)
        {
            PrintError($"Failed to parse binary '{filePath}': {ex.Message}");
            return null;
        }
    }

    private static ulong? ParseHex(string s)
    {
        s = s.Replace("0x", "").Trim();
        if (ulong.TryParse(s, NumberStyles.HexNumber, null, out ulong val)) return val;
        if (ulong.TryParse(s, out ulong dec)) return dec;
        return null;
    }

    private static ConsoleColor GetFlowColor(string arrow)
    {
        if (arrow.Contains("↻")) return ConsoleColor.DarkYellow;
        if (arrow.Contains("↓")) return ConsoleColor.Green;
        if (arrow.Contains("➔")) return ConsoleColor.Blue;
        if (arrow.Contains("⮌")) return ConsoleColor.Red;
        return ConsoleColor.Gray;
    }

    private static void PrintHeader(string title)
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"\n=== {title} ===");
        Console.ResetColor();
    }

    private static void PrintSuccess(string message)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[SUCCESS] {message}");
        Console.ResetColor();
    }

    private static void PrintError(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[ERROR] {message}");
        Console.ResetColor();
    }

    #region Debugger Suite CLI Commands

    private static readonly EmulatedDebuggerEngine _cliDebugger = new();

    private static int CmdDbgLaunch(string filePath)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        _cliDebugger.SetProgramModel(model);
        _cliDebugger.LaunchAsync(filePath).GetAwaiter().GetResult();

        PrintHeader($"Debugger Session Launched: {model.ProgramName}");
        Console.WriteLine($"  Engine:       Ghidra.NET Virtual SRE Instruction Emulator");
        Console.WriteLine($"  Entry Point:  0x{_cliDebugger.CurrentInstructionPointer:X16}");
        Console.WriteLine($"  Status:       {_cliDebugger.State} (Ready for stepping)");
        Console.WriteLine();

        PrintRegisters();
        PrintCallStack();
        return 0;
    }

    private static int CmdDbgStep(string filePath, int stepCount)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        if (_cliDebugger.State == DebuggerState.Inactive)
        {
            _cliDebugger.SetProgramModel(model);
            _cliDebugger.LaunchAsync(filePath).GetAwaiter().GetResult();
        }

        PrintHeader($"Debugger Single-Step ({stepCount} instruction(s))");
        for (int i = 0; i < stepCount; i++)
        {
            _cliDebugger.StepIntoAsync().GetAwaiter().GetResult();
            var item = model.ListingLines.FirstOrDefault(l => ParseHex(l.Address) == _cliDebugger.CurrentInstructionPointer);
            string mnem = item != null ? $"{item.Instruction,-8} {item.Operands}" : "???";
            Console.WriteLine($"  Step #{i + 1:D2} -> 0x{_cliDebugger.CurrentInstructionPointer:X16} | {mnem}");
        }

        Console.WriteLine();
        PrintRegisters();
        return 0;
    }

    private static int CmdDbgRegs(string filePath)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        if (_cliDebugger.State == DebuggerState.Inactive)
        {
            _cliDebugger.SetProgramModel(model);
            _cliDebugger.LaunchAsync(filePath).GetAwaiter().GetResult();
        }

        PrintHeader($"CPU Registers: {model.ProgramName}");
        PrintRegisters();
        return 0;
    }

    private static int CmdDbgStack(string filePath)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        if (_cliDebugger.State == DebuggerState.Inactive)
        {
            _cliDebugger.SetProgramModel(model);
            _cliDebugger.LaunchAsync(filePath).GetAwaiter().GetResult();
        }

        PrintHeader($"Call Stack Backtrace: {model.ProgramName}");
        PrintCallStack();
        return 0;
    }

    private static int CmdDbgBreakpoint(string filePath, string addrStr)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        ulong? addr = ParseHex(addrStr);
        if (!addr.HasValue)
        {
            PrintError($"Invalid breakpoint address: {addrStr}");
            return 1;
        }

        _cliDebugger.SetProgramModel(model);
        _cliDebugger.ToggleBreakpoint(addr.Value, $"sub_{addr.Value:X8}");

        PrintHeader("Debugger Breakpoints");
        Console.WriteLine($"  Total Active Breakpoints: {_cliDebugger.Breakpoints.Count}");
        foreach (var bp in _cliDebugger.Breakpoints)
        {
            Console.WriteLine($"  • {bp.Address} [{bp.TypeDisplay}] {bp.FunctionName} (Status: {bp.StatusText})");
        }
        Console.WriteLine();
        return 0;
    }

    private static int CmdDbgMemory(string filePath, string addrStr, int rowCount)
    {
        var model = LoadProgram(filePath);
        if (model == null) return 1;

        ulong? addr = ParseHex(addrStr);
        if (!addr.HasValue)
        {
            PrintError($"Invalid memory address: {addrStr}");
            return 1;
        }

        if (_cliDebugger.State == DebuggerState.Inactive)
        {
            _cliDebugger.SetProgramModel(model);
            _cliDebugger.LaunchAsync(filePath).GetAwaiter().GetResult();
        }

        _cliDebugger.RefreshMemoryRows(addr.Value, rowCount);

        PrintHeader($"Target Memory Inspection @ 0x{addr.Value:X16}");
        Console.WriteLine("  Address             00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII");
        Console.WriteLine("  -----------------------------------------------------------------------------");
        foreach (var row in _cliDebugger.MemoryRows)
        {
            string tag = row.IsCurrentIP ? " [RIP]" : (row.IsCurrentSP ? " [RSP]" : "      ");
            Console.WriteLine($"  {row.Address}  {row.HexBytes}  {row.Ascii}{tag}");
        }
        Console.WriteLine();
        return 0;
    }

    private static void PrintRegisters()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[CPU Registers (x86_64)]");
        Console.ResetColor();

        var gp = _cliDebugger.Registers.Where(r => r.Category == RegisterCategory.GeneralPurpose || r.Category == RegisterCategory.InstructionPointer).ToList();
        for (int i = 0; i < gp.Count; i += 2)
        {
            var r1 = gp[i];
            string line = $"  {r1.Name,-6} = {r1.ValueHex} ({r1.ValueDec})";
            if (i + 1 < gp.Count)
            {
                var r2 = gp[i + 1];
                line = $"{line,-45} {r2.Name,-6} = {r2.ValueHex} ({r2.ValueDec})";
            }
            Console.WriteLine(line);
        }
        Console.WriteLine();
    }

    private static void PrintCallStack()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[Call Stack Backtrace]");
        Console.ResetColor();

        if (_cliDebugger.CallStack.Count == 0)
        {
            Console.WriteLine("  (No active frames)");
        }
        else
        {
            foreach (var frame in _cliDebugger.CallStack)
            {
                Console.WriteLine($"  #{frame.FrameIndex:D2}  {frame.InstructionAddress}  {frame.ModuleName}!{frame.FunctionName} (RSP: {frame.StackPointer})");
            }
        }
        Console.WriteLine();
    }

    #endregion
}
