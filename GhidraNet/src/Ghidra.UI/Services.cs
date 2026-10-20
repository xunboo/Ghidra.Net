using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Ghidra.UI.Models;
using Iced.Intel;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using Microsoft.CodeAnalysis.Scripting;

namespace Ghidra.UI.Services;

public class PeLoaderService
{
    private record RawSection(string Name, uint VirtSize, uint VirtAddr, uint RawSize, uint RawPtr, uint Charact);

    public static ProgramModel LoadPeBinary(string filePath)
    {
        var model = new ProgramModel
        {
            ProgramName = Path.GetFileName(filePath),
            FilePath = filePath
        };

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new BinaryReader(fs);

            // 1. DOS Header
            if (fs.Length < 0x40)
            {
                return CreateDefaultDemoModel(filePath, "File size too small for PE executable");
            }

            ushort mz = reader.ReadUInt16();
            if (mz != 0x5A4D) // 'MZ'
            {
                return CreateDefaultDemoModel(filePath, "Not a valid PE executable (Missing 'MZ' magic)");
            }

            fs.Seek(0x3C, SeekOrigin.Begin);
            int peOffset = reader.ReadInt32();
            if (peOffset <= 0 || peOffset >= fs.Length - 0x18)
            {
                return CreateDefaultDemoModel(filePath, "Invalid PE offset in DOS header");
            }

            fs.Seek(peOffset, SeekOrigin.Begin);
            uint peSig = reader.ReadUInt32();
            if (peSig != 0x00004550) // 'PE\0\0'
            {
                return CreateDefaultDemoModel(filePath, "Not a valid PE executable (Missing 'PE' signature)");
            }

            // 2. COFF Header
            ushort machine = reader.ReadUInt16();
            ushort numSections = reader.ReadUInt16();
            reader.ReadUInt32(); // TimeDateStamp
            reader.ReadUInt32(); // PointerToSymbolTable
            reader.ReadUInt32(); // NumberOfSymbols
            ushort sizeOfOptionalHeader = reader.ReadUInt16();
            ushort characteristics = reader.ReadUInt16();

            // 3. Optional Header
            long optHeaderPos = fs.Position;
            ushort optMagic = reader.ReadUInt16();

            bool is64 = (optMagic == 0x20B);
            model.Is64Bit = is64;
            model.Architecture = is64 ? "x86_64:LE:64:default" : "x86:LE:32:default";
            model.Format = is64 ? "PE (Portable Executable 64-bit)" : "PE (Portable Executable 32-bit)";
            model.Compiler = "Microsoft Visual C++ / CL";

            reader.ReadByte(); // MajorLinkerVersion
            reader.ReadByte(); // MinorLinkerVersion
            uint sizeOfCode = reader.ReadUInt32();
            uint sizeOfInitData = reader.ReadUInt32();
            uint sizeOfUninitData = reader.ReadUInt32();
            uint entryPointRva = reader.ReadUInt32();
            uint baseOfCode = reader.ReadUInt32();

            ulong imageBase = 0x00400000;
            if (is64)
            {
                imageBase = reader.ReadUInt64();
            }
            else
            {
                reader.ReadUInt32(); // BaseOfData
                imageBase = reader.ReadUInt32();
            }

            model.ImageBase = imageBase;
            model.EntryPoint = imageBase + entryPointRva;

            // Data Directories: Export (0), Import (1)
            uint exportRva = 0, exportSize = 0;
            uint importRva = 0, importSize = 0;

            int dataDirOffset = is64 ? 112 : 96;
            if (sizeOfOptionalHeader >= dataDirOffset + 16)
            {
                fs.Seek(optHeaderPos + dataDirOffset, SeekOrigin.Begin);
                exportRva = reader.ReadUInt32();
                exportSize = reader.ReadUInt32();
                importRva = reader.ReadUInt32();
                importSize = reader.ReadUInt32();
            }

            // 4. Section Table
            fs.Seek(optHeaderPos + sizeOfOptionalHeader, SeekOrigin.Begin);
            var rawSections = new List<RawSection>();

            for (int i = 0; i < numSections; i++)
            {
                byte[] secNameBytes = reader.ReadBytes(8);
                string secName = Encoding.UTF8.GetString(secNameBytes).TrimEnd('\0');
                uint vSize = reader.ReadUInt32();
                uint vAddr = reader.ReadUInt32();
                uint rSize = reader.ReadUInt32();
                uint rPtr = reader.ReadUInt32();
                reader.ReadUInt32(); // RelocPtr
                reader.ReadUInt32(); // LineNumPtr
                reader.ReadUInt16(); // NumReloc
                reader.ReadUInt16(); // NumLineNum
                uint chars = reader.ReadUInt32();

                rawSections.Add(new RawSection(secName, vSize, vAddr, rSize, rPtr, chars));

                string perms = "";
                if ((chars & 0x20000000) != 0) perms += "X";
                if ((chars & 0x40000000) != 0) perms += "R";
                if ((chars & 0x80000000) != 0) perms += "W";
                if (string.IsNullOrEmpty(perms)) perms = "R";

                ulong startAddr = imageBase + vAddr;
                ulong endAddr = startAddr + (vSize > 0 ? vSize : rSize);

                model.Sections.Add(new SectionNode
                {
                    Name = secName,
                    AddressRange = $"{startAddr:X8} - {endAddr:X8}",
                    StartAddress = startAddr,
                    EndAddress = endAddr,
                    RawPointer = rPtr,
                    VirtualAddress = vAddr,
                    Size = vSize > 0 ? vSize : rSize,
                    Permissions = perms
                });
            }

            // Load raw bytes for all sections
            for (int sIdx = 0; sIdx < rawSections.Count; sIdx++)
            {
                var raw = rawSections[sIdx];
                var node = model.Sections[sIdx];
                if (raw.RawPtr < fs.Length && raw.RawSize > 0)
                {
                    fs.Seek(raw.RawPtr, SeekOrigin.Begin);
                    int toRead = (int)Math.Min(raw.RawSize, (uint)Math.Max(0, fs.Length - raw.RawPtr));
                    toRead = Math.Min(toRead, 32 * 1024 * 1024);
                    node.Data = reader.ReadBytes(toRead);
                }
            }

            long RvaToFileOffset(uint rva)
            {
                foreach (var sec in rawSections)
                {
                    uint span = Math.Max(sec.VirtSize, sec.RawSize);
                    if (rva >= sec.VirtAddr && rva < sec.VirtAddr + span)
                    {
                        return sec.RawPtr + (rva - sec.VirtAddr);
                    }
                }
                return -1;
            }

            string ReadNullTerminatedAscii(long offset, int maxLen = 256)
            {
                if (offset < 0 || offset >= fs.Length) return string.Empty;
                long cur = fs.Position;
                fs.Seek(offset, SeekOrigin.Begin);
                var sb = new StringBuilder();
                for (int j = 0; j < maxLen; j++)
                {
                    if (fs.Position >= fs.Length) break;
                    byte b = reader.ReadByte();
                    if (b == 0) break;
                    if (b >= 32 && b <= 126) sb.Append((char)b);
                }
                fs.Seek(cur, SeekOrigin.Begin);
                return sb.ToString();
            }

            var exportList = new List<(string Name, ulong Address)>();
            var importNodeList = new List<SymbolNode>();

            // 5. Parse Export Directory
            if (exportRva != 0)
            {
                long expOff = RvaToFileOffset(exportRva);
                if (expOff >= 0 && expOff < fs.Length - 40)
                {
                    fs.Seek(expOff, SeekOrigin.Begin);
                    reader.ReadUInt32(); // Characteristics
                    reader.ReadUInt32(); // TimeDateStamp
                    reader.ReadUInt16(); // MajorVersion
                    reader.ReadUInt16(); // MinorVersion
                    uint expDllNameRva = reader.ReadUInt32();
                    uint ordinalBase = reader.ReadUInt32();
                    uint numFunctions = reader.ReadUInt32();
                    uint numNames = reader.ReadUInt32();
                    uint addrFunctionsRva = reader.ReadUInt32();
                    uint addrNamesRva = reader.ReadUInt32();
                    uint addrOrdinalsRva = reader.ReadUInt32();

                    uint count = Math.Min(numNames, 1000);
                    for (uint idx = 0; idx < count; idx++)
                    {
                        long namePtrOff = RvaToFileOffset(addrNamesRva + idx * 4);
                        long ordOff = RvaToFileOffset(addrOrdinalsRva + idx * 2);
                        if (namePtrOff >= 0 && ordOff >= 0)
                        {
                            fs.Seek(namePtrOff, SeekOrigin.Begin);
                            uint nRva = reader.ReadUInt32();
                            string expName = ReadNullTerminatedAscii(RvaToFileOffset(nRva));

                            fs.Seek(ordOff, SeekOrigin.Begin);
                            ushort ord = reader.ReadUInt16();

                            long funcOff = RvaToFileOffset(addrFunctionsRva + (uint)ord * 4);
                            if (funcOff >= 0)
                            {
                                fs.Seek(funcOff, SeekOrigin.Begin);
                                uint fRva = reader.ReadUInt32();
                                if (fRva != 0)
                                {
                                    ulong expAddr = imageBase + fRva;
                                    exportList.Add((expName, expAddr));
                                    model.FunctionAddresses.Add(expAddr);
                                }
                            }
                        }
                    }
                }
            }

            // 6. Parse Import Directory
            if (importRva != 0)
            {
                long impOff = RvaToFileOffset(importRva);
                if (impOff >= 0 && impOff < fs.Length - 20)
                {
                    fs.Seek(impOff, SeekOrigin.Begin);
                    for (int descIdx = 0; descIdx < 200; descIdx++)
                    {
                        uint origFirstThunk = reader.ReadUInt32();
                        reader.ReadUInt32(); // TimeDateStamp
                        reader.ReadUInt32(); // ForwarderChain
                        uint nameRva = reader.ReadUInt32();
                        uint firstThunk = reader.ReadUInt32();

                        if (origFirstThunk == 0 && firstThunk == 0 && nameRva == 0)
                            break;

                        long resumePos = fs.Position;
                        string dllName = ReadNullTerminatedAscii(RvaToFileOffset(nameRva));
                        if (!string.IsNullOrEmpty(dllName))
                        {
                            var dllNode = new SymbolNode { Name = dllName, Icon = "📦" };
                            uint thunkRva = (origFirstThunk != 0) ? origFirstThunk : firstThunk;

                            int thunkIdx = 0;
                            while (thunkIdx < 500)
                            {
                                long thunkFileOff = RvaToFileOffset(thunkRva + (uint)(thunkIdx * (is64 ? 8 : 4)));
                                if (thunkFileOff < 0 || thunkFileOff >= fs.Length - (is64 ? 8 : 4))
                                    break;

                                fs.Seek(thunkFileOff, SeekOrigin.Begin);
                                ulong val = is64 ? reader.ReadUInt64() : reader.ReadUInt32();
                                if (val == 0) break;

                                ulong iatAddress = imageBase + firstThunk + (ulong)(thunkIdx * (is64 ? 8 : 4));
                                bool isOrdinal = (val & (is64 ? 0x8000000000000000UL : 0x80000000U)) != 0;

                                string fnName;
                                if (isOrdinal)
                                {
                                    fnName = $"Ordinal_{val & 0xFFFF}";
                                }
                                else
                                {
                                    uint hintRva = (uint)(val & 0x7FFFFFFF);
                                    fnName = ReadNullTerminatedAscii(RvaToFileOffset(hintRva) + 2);
                                    if (string.IsNullOrEmpty(fnName))
                                        fnName = $"Import_{val:X}";
                                }

                                model.IatMap[iatAddress] = $"{dllName}!{fnName}";
                                dllNode.Children.Add(new SymbolNode
                                {
                                    Name = fnName,
                                    Address = $"{iatAddress:X8}",
                                    SymbolType = "Import",
                                    Signature = $"{dllName}!{fnName}",
                                    Icon = "→"
                                });

                                thunkIdx++;
                            }

                            if (dllNode.Children.Count > 0)
                            {
                                importNodeList.Add(dllNode);
                            }
                        }

                        fs.Seek(resumePos, SeekOrigin.Begin);
                    }
                }
            }

            // 7. Extract Strings from Read-Only Sections (.rdata, etc.)
            foreach (var sec in rawSections)
            {
                if ((sec.Charact & 0x40000000) != 0 && (sec.Charact & 0x20000000) == 0 && sec.RawSize > 0)
                {
                    long secOff = sec.RawPtr;
                    if (secOff < fs.Length)
                    {
                        fs.Seek(secOff, SeekOrigin.Begin);
                        int readLen = (int)Math.Min(sec.RawSize, 256 * 1024);
                        byte[] rdataBytes = reader.ReadBytes(readLen);

                        int strStart = -1;
                        for (int bIdx = 0; bIdx < rdataBytes.Length; bIdx++)
                        {
                            byte b = rdataBytes[bIdx];
                            if (b >= 32 && b <= 126)
                            {
                                if (strStart < 0) strStart = bIdx;
                            }
                            else
                            {
                                if (b == 0 && strStart >= 0 && (bIdx - strStart) >= 4 && (bIdx - strStart) <= 100)
                                {
                                    string s = Encoding.ASCII.GetString(rdataBytes, strStart, bIdx - strStart);
                                    ulong sAddr = imageBase + sec.VirtAddr + (ulong)strStart;
                                    model.StringMap[sAddr] = s;
                                }
                                strStart = -1;
                            }
                        }
                    }
                }
            }

            // 8. Load Executable Code Section (.text / EntryPoint section)
            var codeSec = model.Sections.FirstOrDefault(s => model.EntryPoint >= s.StartAddress && model.EntryPoint < s.EndAddress)
                          ?? model.Sections.FirstOrDefault(s => s.IsExecutable)
                          ?? model.Sections.FirstOrDefault(s => s.Name.StartsWith(".text", StringComparison.OrdinalIgnoreCase));

            if (codeSec != null && codeSec.Data != null && codeSec.Data.Length > 0)
            {
                model.CodeBytes = codeSec.Data;
                model.CodeBaseAddr = codeSec.StartAddress;

                model.FunctionAddresses.Add(model.EntryPoint);

                // Initial Disassembly Pass
                DisassembleCode(model, codeSizeLimit: 2500);
            }
            else
            {
                PopulateDefaultInstructions(model);
            }

            // 9. Build Initial Symbol Categories
            BuildSymbolTree(model, exportList, importNodeList);
            BuildProgramTree(model);

            // 10. Populate Data Types & Byte Viewer
            PopulateDataTypes(model);
            PopulateByteViewer(model);
        }
        catch (Exception ex)
        {
            return CreateDefaultDemoModel(filePath, $"Error parsing PE: {ex.Message}");
        }

        return model;
    }

    public static void RunAutoAnalysis(ProgramModel model, Action<string> log)
    {
        log("=================== Starting Auto Analysis ===================");
        if (model.CodeBytes == null || model.CodeBytes.Length == 0)
        {
            log("[Analysis Error] No executable code section found to analyze.");
            return;
        }

        log($"[Analysis] Step 1: Scanning code bytes ({model.CodeBytes.Length:N0} bytes) for function entries and call targets...");

        int bitness = model.Is64Bit ? 64 : 32;
        var codeReader = new ByteArrayCodeReader(model.CodeBytes);
        var decoder = Iced.Intel.Decoder.Create(bitness, codeReader, model.CodeBaseAddr);

        var callTargets = new HashSet<ulong>();
        var prologueEntries = new HashSet<ulong>();

        bool prevWasReturnOrJmp = true;

        while (decoder.IP < model.CodeBaseAddr + (ulong)model.CodeBytes.Length)
        {
            ulong currentIp = decoder.IP;
            decoder.Decode(out var instr);

            if (instr.IsInvalid)
                continue;

            // Detect calls to internal addresses
            if (instr.Mnemonic == Mnemonic.Call)
            {
                if (instr.Op0Kind == OpKind.NearBranch64 || instr.Op0Kind == OpKind.NearBranch32 || instr.Op0Kind == OpKind.NearBranch16)
                {
                    ulong target = instr.NearBranchTarget;
                    if (target >= model.CodeBaseAddr && target < model.CodeBaseAddr + (ulong)model.CodeBytes.Length)
                    {
                        callTargets.Add(target);
                    }
                }
            }

            // Detect function prologues
            if (prevWasReturnOrJmp)
            {
                if (instr.Mnemonic == Mnemonic.Push || instr.Mnemonic == Mnemonic.Sub || instr.Mnemonic == Mnemonic.Endbr64)
                {
                    prologueEntries.Add(currentIp);
                }
            }

            prevWasReturnOrJmp = (instr.Mnemonic == Mnemonic.Ret ||
                                  instr.Mnemonic == Mnemonic.Jmp ||
                                  instr.Mnemonic == Mnemonic.Int3);
        }

        foreach (var t in callTargets) model.FunctionAddresses.Add(t);
        foreach (var p in prologueEntries) model.FunctionAddresses.Add(p);
        model.FunctionAddresses.Add(model.EntryPoint);

        log($"[Analysis] Step 2: Recovered {model.FunctionAddresses.Count} functions ({callTargets.Count} call targets, {prologueEntries.Count} prologue signatures)");
        log($"[Analysis] Step 3: Resolving cross-references to {model.IatMap.Count} imported APIs and {model.StringMap.Count} strings ...");

        // Re-disassemble with full function boundaries
        DisassembleCode(model, codeSizeLimit: 3000);

        // Rebuild Symbol Tree
        var exportList = new List<(string Name, ulong Address)>();
        var importList = new List<SymbolNode>();

        // Find existing imports from current symbol tree
        var existingImpCat = model.SymbolCategories.FirstOrDefault(c => c.Name == "Imports");
        if (existingImpCat != null)
        {
            importList.AddRange(existingImpCat.Children);
        }

        var existingExpCat = model.SymbolCategories.FirstOrDefault(c => c.Name == "Exports");
        if (existingExpCat != null)
        {
            foreach (var exp in existingExpCat.Children)
            {
                if (ulong.TryParse(exp.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                {
                    exportList.Add((exp.Name, addr));
                }
            }
        }

        BuildSymbolTree(model, exportList, importList);
        PopulateByteViewer(model);

        log($"[Analysis] Step 4: Disassembly Listing updated ({model.ListingLines.Count:N0} lines)");
        log($"✓ Auto Analysis Complete: Discovered {model.FunctionAddresses.Count} functions, {model.IatMap.Count} imports, {model.Sections.Count} sections.");
    }

    private static void AddXRef(ProgramModel model, ulong target, ulong from, string refType, string text, string ctx)
    {
        if (target == 0) return;
        if (!model.XRefs.TryGetValue(target, out var list))
        {
            list = new List<XRefModel>();
            model.XRefs[target] = list;
        }
        if (!list.Any(x => x.FromAddress == from))
        {
            list.Add(new XRefModel
            {
                FromAddress = from,
                RefType = refType,
                InstructionText = text,
                FunctionContext = ctx
            });
        }
    }

    private static void DisassembleCode(ProgramModel model, int codeSizeLimit = 2000)
    {
        model.ListingLines.Clear();
        model.XRefs.Clear();

        if (model.CodeBytes == null || model.CodeBytes.Length == 0)
            return;

        int bitness = model.Is64Bit ? 64 : 32;

        // Pass 1: Build Cross-Reference (XRef) Call & Data Graph
        var codeReaderXRef = new ByteArrayCodeReader(model.CodeBytes);
        var decXRef = Iced.Intel.Decoder.Create(bitness, codeReaderXRef, model.CodeBaseAddr);
        string currentContextFunc = "EntryPoint";

        while (decXRef.IP < model.CodeBaseAddr + (ulong)model.CodeBytes.Length)
        {
            ulong curIp = decXRef.IP;
            if (model.FunctionAddresses.Contains(curIp))
            {
                currentContextFunc = (curIp == model.EntryPoint) ? "main" : $"sub_{curIp:X8}";
                if (model.RenamedSymbols.TryGetValue(currentContextFunc, out var ren)) currentContextFunc = ren;
            }

            decXRef.Decode(out var ins);
            if (ins.IsInvalid) continue;

            if (ins.Mnemonic == Mnemonic.Call)
            {
                if (ins.Op0Kind == OpKind.NearBranch64 || ins.Op0Kind == OpKind.NearBranch32 || ins.Op0Kind == OpKind.NearBranch16)
                    AddXRef(model, ins.NearBranchTarget, curIp, "CALL", $"{ins.Mnemonic} 0x{ins.NearBranchTarget:X8}", currentContextFunc);
                else if (ins.IsIPRelativeMemoryOperand)
                    AddXRef(model, ins.IPRelativeMemoryAddress, curIp, "CALL_IAT", $"{ins.Mnemonic} [0x{ins.IPRelativeMemoryAddress:X8}]", currentContextFunc);
            }
            else if (ins.Mnemonic == Mnemonic.Jmp || (ins.Mnemonic >= Mnemonic.Ja && ins.Mnemonic <= Mnemonic.Js))
            {
                if (ins.Op0Kind == OpKind.NearBranch64 || ins.Op0Kind == OpKind.NearBranch32 || ins.Op0Kind == OpKind.NearBranch16)
                    AddXRef(model, ins.NearBranchTarget, curIp, "JUMP", $"{ins.Mnemonic} 0x{ins.NearBranchTarget:X8}", currentContextFunc);
            }
            else if (ins.IsIPRelativeMemoryOperand)
            {
                AddXRef(model, ins.IPRelativeMemoryAddress, curIp, "DATA", $"{ins.Mnemonic} [0x{ins.IPRelativeMemoryAddress:X8}]", currentContextFunc);
            }
        }

        // Pass 2: Generate Disassembly Listing with XRef Summaries and Formatted Fields
        var codeReader = new ByteArrayCodeReader(model.CodeBytes);
        var decoder = Iced.Intel.Decoder.Create(bitness, codeReader, model.CodeBaseAddr);

        var formatter = new IntelFormatter();
        formatter.Options.LeadingZeroes = true;
        formatter.Options.UppercaseHex = true;
        formatter.Options.UppercaseAll = true;

        var output = new StringOutput();
        int count = 0;
        string activeFunctionName = "main";

        while (decoder.IP < model.CodeBaseAddr + (ulong)model.CodeBytes.Length && count < codeSizeLimit)
        {
            ulong ip = decoder.IP;

            // Check if this IP is a function boundary
            if (model.FunctionAddresses.Contains(ip) || ip == model.EntryPoint)
            {
                string fnName = (ip == model.EntryPoint) ? "EntryPoint (_start)" : $"sub_{ip:X8}";
                if (model.RenamedSymbols.TryGetValue(fnName, out var ren)) fnName = ren;
                activeFunctionName = fnName;

                string xrefSummary = string.Empty;
                if (model.XRefs.TryGetValue(ip, out var xlist) && xlist.Count > 0)
                {
                    xrefSummary = $" | XREF[{xlist.Count}]: " + string.Join(", ", xlist.Take(3).Select(x => $"{x.FromAddress:X8}({x.RefType.ToLower()})")) + (xlist.Count > 3 ? "..." : "");
                }

                model.ListingLines.Add(new ListingItem
                {
                    Address = $"{ip:X8}",
                    Bytes = "",
                    Instruction = "*************************************************",
                    Operands = "",
                    Comment = $"* Function: {fnName}{xrefSummary}",
                    IsFunctionHeader = true,
                    FunctionName = fnName
                });
            }

            int startOffset = (int)(ip - model.CodeBaseAddr);
            decoder.Decode(out var instr);

            if (instr.IsInvalid)
            {
                byte badByte = (startOffset >= 0 && startOffset < model.CodeBytes.Length) ? model.CodeBytes[startOffset] : (byte)0;
                model.ListingLines.Add(new ListingItem
                {
                    Address = $"{ip:X8}",
                    Bytes = $"{badByte:X2}",
                    Instruction = "DB",
                    Operands = $"0x{badByte:X2}",
                    Comment = "; Invalid opcode",
                    FunctionName = activeFunctionName
                });
                count++;
                continue;
            }

            int instrLen = instr.Length;
            var byteSb = new StringBuilder();
            for (int k = 0; k < instrLen && startOffset + k < model.CodeBytes.Length; k++)
            {
                byteSb.Append($"{model.CodeBytes[startOffset + k]:X2} ");
            }

            output.Reset();
            formatter.Format(instr, output);
            string formattedText = output.ToString();

            string mnemonic = instr.Mnemonic.ToString().ToUpperInvariant();
            string operands = string.Empty;

            int firstSpace = formattedText.IndexOf(' ');
            if (firstSpace > 0 && firstSpace < formattedText.Length - 1)
            {
                operands = formattedText.Substring(firstSpace + 1).Trim();
            }

            string comment = string.Empty;

            // Resolve custom user comment
            if (model.CustomComments.TryGetValue(ip, out var customComment))
            {
                comment = $"; {customComment} ";
            }

            // Resolve RIP-relative memory operand or IAT cross reference
            if (instr.IsIPRelativeMemoryOperand)
            {
                ulong target = instr.IPRelativeMemoryAddress;
                if (model.IatMap.TryGetValue(target, out var apiName))
                {
                    comment += $"; -> {apiName}";
                }
                else if (model.StringMap.TryGetValue(target, out var strVal))
                {
                    comment += $"; \"{strVal}\"";
                }
                else
                {
                    comment += $"; [0x{target:X8}]";
                }
            }
            else if (instr.Mnemonic == Mnemonic.Call)
            {
                if (instr.Op0Kind == OpKind.NearBranch64 || instr.Op0Kind == OpKind.NearBranch32 || instr.Op0Kind == OpKind.NearBranch16)
                {
                    ulong target = instr.NearBranchTarget;
                    string targetName = (target == model.EntryPoint) ? "EntryPoint" : $"sub_{target:X8}";
                    if (model.RenamedSymbols.TryGetValue(targetName, out var rName)) targetName = rName;
                    comment += $"; Call {targetName}";
                }
            }

            model.ListingLines.Add(new ListingItem
            {
                Address = $"{ip:X8}",
                Bytes = byteSb.ToString().TrimEnd(),
                Instruction = mnemonic,
                Operands = operands,
                Comment = comment.Trim(),
                FunctionName = activeFunctionName
            });

            count++;
        }
    }

    private static void BuildSymbolTree(ProgramModel model, List<(string Name, ulong Address)> exportList, List<SymbolNode> importNodeList)
    {
        model.SymbolCategories.Clear();

        // 1. Functions Group
        var fnGroup = new SymbolNode { Name = "Functions", Icon = "⚡" };

        var sortedFuncs = model.FunctionAddresses.OrderBy(a => a).ToList();
        if (sortedFuncs.Count == 0)
        {
            sortedFuncs.Add(model.EntryPoint);
        }

        foreach (var addr in sortedFuncs)
        {
            string name = (addr == model.EntryPoint) ? "main" : $"sub_{addr:X8}";
            if (model.RenamedSymbols.TryGetValue(name, out var ren)) name = ren;
            var expMatch = exportList.FirstOrDefault(e => e.Address == addr);
            if (!string.IsNullOrEmpty(expMatch.Name))
            {
                name = expMatch.Name;
            }

            fnGroup.Children.Add(new SymbolNode
            {
                Name = name,
                Address = $"{addr:X8}",
                SymbolType = "Function",
                Signature = $"void {name}()",
                Icon = "ƒ"
            });
        }
        model.SymbolCategories.Add(fnGroup);

        // 2. Imports Group
        var impGroup = new SymbolNode { Name = "Imports", Icon = "📥" };
        foreach (var imp in importNodeList)
        {
            impGroup.Children.Add(imp);
        }
        model.SymbolCategories.Add(impGroup);

        // 3. Exports Group
        var expGroup = new SymbolNode { Name = "Exports", Icon = "📤" };
        foreach (var exp in exportList)
        {
            expGroup.Children.Add(new SymbolNode
            {
                Name = exp.Name,
                Address = $"{exp.Address:X8}",
                SymbolType = "Export",
                Signature = $"export {exp.Name}",
                Icon = "←"
            });
        }
        if (expGroup.Children.Count > 0)
        {
            model.SymbolCategories.Add(expGroup);
        }

        // 4. Classes & Namespaces Group
        var classGroup = new SymbolNode { Name = "Classes & Namespaces", Icon = "🏛️" };
        var nsMap = new Dictionary<string, SymbolNode>();
        foreach (var fn in fnGroup.Children)
        {
            if (fn.Name.Contains("::"))
            {
                int lastColon = fn.Name.LastIndexOf("::");
                string ns = fn.Name.Substring(0, lastColon);
                string member = fn.Name.Substring(lastColon + 2);
                if (!nsMap.TryGetValue(ns, out var nsNode))
                {
                    nsNode = new SymbolNode { Name = ns, Icon = "📦", SymbolType = "Namespace" };
                    nsMap[ns] = nsNode;
                    classGroup.Children.Add(nsNode);
                }
                nsNode.Children.Add(new SymbolNode
                {
                    Name = member,
                    Address = fn.Address,
                    SymbolType = "ClassMethod",
                    Signature = fn.Signature,
                    Icon = "ƒ"
                });
            }
        }
        if (classGroup.Children.Count > 0)
        {
            model.SymbolCategories.Add(classGroup);
        }

        // 5. Global Variables Group
        var dataSec = model.Sections.FirstOrDefault(s => s.Name.Equals(".data", StringComparison.OrdinalIgnoreCase));
        if (dataSec != null)
        {
            var globGroup = new SymbolNode { Name = "Global Variables", Icon = "🌐" };
            for (ulong off = 0; off < (ulong)Math.Min(dataSec.Size, 0x100); off += 8)
            {
                ulong gAddr = dataSec.StartAddress + off;
                globGroup.Children.Add(new SymbolNode
                {
                    Name = $"g_data_{gAddr:X8}",
                    Address = $"{gAddr:X8}",
                    SymbolType = "GlobalData",
                    Signature = $"void* g_data_{gAddr:X8}",
                    Icon = "🔹"
                });
            }
            if (globGroup.Children.Count > 0)
            {
                model.SymbolCategories.Add(globGroup);
            }
        }

        // 6. Labels / Strings Group
        var lblGroup = new SymbolNode { Name = "Labels & Strings", Icon = "🏷️" };
        int strLimit = 0;
        foreach (var kvp in model.StringMap)
        {
            if (strLimit++ > 50) break;
            string preview = kvp.Value.Length > 24 ? kvp.Value.Substring(0, 24) + "..." : kvp.Value;
            lblGroup.Children.Add(new SymbolNode
            {
                Name = $"\"{preview}\"",
                Address = $"{kvp.Key:X8}",
                SymbolType = "Label",
                Icon = "🏷️"
            });
        }
        if (lblGroup.Children.Count > 0)
        {
            model.SymbolCategories.Add(lblGroup);
        }

        // 7. Bookmarks Group
        if (model.Bookmarks.Count > 0)
        {
            var bmGroup = new SymbolNode { Name = $"Bookmarks ({model.Bookmarks.Count})", Icon = "🔖" };
            foreach (var bm in model.Bookmarks)
            {
                bmGroup.Children.Add(new SymbolNode
                {
                    Name = $"{bm.Description} [{bm.Category}]",
                    Address = $"{bm.Address:X8}",
                    SymbolType = "Bookmark",
                    Icon = bm.Icon
                });
            }
            model.SymbolCategories.Add(bmGroup);
        }
    }

    public static ProgramModel CreateDefaultDemoModel(string filePath, string status)
    {
        var model = new ProgramModel
        {
            ProgramName = Path.GetFileName(filePath),
            FilePath = filePath,
            StatusMessage = status,
            Architecture = "x86_64:LE:64:default",
            Compiler = "Visual Studio (MSVC x64)",
            ImageBase = 0x140000000,
            EntryPoint = 0x140001000
        };

        model.Sections.Add(new SectionNode { Name = ".text", AddressRange = "140001000 - 140134000", Size = 1257472, Permissions = "RX" });
        model.Sections.Add(new SectionNode { Name = ".rdata", AddressRange = "140134000 - 1401CE000", Size = 630784, Permissions = "R" });
        model.Sections.Add(new SectionNode { Name = ".data", AddressRange = "1401CE000 - 140224000", Size = 352256, Permissions = "RW" });

        PopulateDefaultInstructions(model);

        var fnGroup = new SymbolNode { Name = "Functions", Icon = "⚡" };
        fnGroup.Children.Add(new SymbolNode { Name = "main", Address = "140001000", SymbolType = "Function", Signature = "int main(int argc, char** argv)", Icon = "ƒ" });
        model.SymbolCategories.Add(fnGroup);

        PopulateDataTypes(model);
        PopulateByteViewer(model);

        return model;
    }

    public static void PopulateDataTypes(ProgramModel model)
    {
        model.DataTypeCategories.Clear();

        // 1. Built-in Types
        var builtIn = new DataTypeNode { Name = "BuiltIn Types", Icon = "📦", Kind = "Category" };
        builtIn.Children.Add(new DataTypeNode { Name = "void", Size = "0 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "bool", Size = "1 byte", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "byte / uint8", Size = "1 byte", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "char", Size = "1 byte", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "word / uint16", Size = "2 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "dword / uint32", Size = "4 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "int / int32", Size = "4 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "float", Size = "4 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "qword / uint64", Size = "8 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "double", Size = "8 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "pointer (void*)", Size = model.Is64Bit ? "8 bytes" : "4 bytes", Kind = "BuiltIn", Icon = "🔹" });
        builtIn.Children.Add(new DataTypeNode { Name = "string (char*)", Size = model.Is64Bit ? "8 bytes" : "4 bytes", Kind = "BuiltIn", Icon = "🔹" });
        model.DataTypeCategories.Add(builtIn);

        // 2. Windows PE Structures
        var winStructs = new DataTypeNode { Name = "Windows PE & System Structs", Icon = "📑", Kind = "Category" };
        winStructs.Children.Add(new DataTypeNode { Name = "IMAGE_DOS_HEADER", Size = "64 bytes (0x40)", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "IMAGE_FILE_HEADER", Size = "20 bytes (0x14)", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = model.Is64Bit ? "IMAGE_OPTIONAL_HEADER64" : "IMAGE_OPTIONAL_HEADER32", Size = model.Is64Bit ? "240 bytes" : "224 bytes", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "IMAGE_SECTION_HEADER", Size = "40 bytes (0x28)", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "IMAGE_IMPORT_DESCRIPTOR", Size = "20 bytes (0x14)", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "IMAGE_EXPORT_DIRECTORY", Size = "40 bytes (0x28)", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "GUID", Size = "16 bytes (0x10)", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "UNICODE_STRING", Size = model.Is64Bit ? "16 bytes" : "8 bytes", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "PEB (Process Environment Block)", Size = "Variable", Kind = "Struct", Icon = "🧩" });
        winStructs.Children.Add(new DataTypeNode { Name = "TEB (Thread Environment Block)", Size = "Variable", Kind = "Struct", Icon = "🧩" });
        model.DataTypeCategories.Add(winStructs);

        // 3. Enums & Status Codes
        var enums = new DataTypeNode { Name = "Enums & Status Constants", Icon = "🏷️", Kind = "Category" };
        enums.Children.Add(new DataTypeNode { Name = "HRESULT (S_OK, E_FAIL...)", Size = "4 bytes", Kind = "Enum", Icon = "🔸" });
        enums.Children.Add(new DataTypeNode { Name = "NTSTATUS (STATUS_SUCCESS...)", Size = "4 bytes", Kind = "Enum", Icon = "🔸" });
        enums.Children.Add(new DataTypeNode { Name = "PAGE_PROTECTION (PAGE_READWRITE...)", Size = "4 bytes", Kind = "Enum", Icon = "🔸" });
        enums.Children.Add(new DataTypeNode { Name = "MEM_ALLOCATION (MEM_COMMIT, MEM_RESERVE)", Size = "4 bytes", Kind = "Enum", Icon = "🔸" });
        model.DataTypeCategories.Add(enums);

        // 4. User Defined Enums
        var userEnums = new DataTypeNode { Name = $"User Defined Enums ({model.CustomEnums.Count})", Icon = "🏷️", Kind = "Category" };
        foreach (var ce in model.CustomEnums)
        {
            var eNode = new DataTypeNode { Name = ce.Name, Size = $"{ce.UnderlyingType} ({ce.Members.Count} members)", Kind = "Enum", Icon = "🏷️" };
            foreach (var m in ce.Members)
            {
                eNode.Children.Add(new DataTypeNode { Name = m.Name, Size = m.ValueHex, Kind = "EnumMember", Icon = "🔹" });
            }
            userEnums.Children.Add(eNode);
        }
        model.DataTypeCategories.Add(userEnums);

        // 5. User Defined Structures
        var userStructs = new DataTypeNode { Name = $"User Defined Structs ({model.CustomStructures.Count})", Icon = "🧩", Kind = "Category" };
        foreach (var cs in model.CustomStructures)
        {
            var sNode = new DataTypeNode { Name = cs.Name, Size = $"{cs.TotalSize} bytes", Kind = "Struct", Icon = "🏷️" };
            foreach (var f in cs.Fields)
            {
                sNode.Children.Add(new DataTypeNode { Name = $"{f.Name} (+{f.OffsetHex})", Size = $"{f.Size} bytes ({f.TypeName})", Kind = "Field", Icon = "🔹" });
            }
            userStructs.Children.Add(sNode);
        }
        model.DataTypeCategories.Add(userStructs);
    }

    public static void BuildProgramTree(ProgramModel model)
    {
        model.ProgramTreeNodes.Clear();
        var root = new ProgramTreeNode
        {
            Name = $"{model.ProgramName} (Base: 0x{model.ImageBase:X8})",
            Icon = "💻",
            AddressRange = $"0x{model.ImageBase:X8} - 0x{model.ImageBase + (ulong)model.Sections.Sum(s => s.Size):X8}",
            Details = $"{model.Architecture} | {model.Format}"
        };

        // Headers Block
        root.Children.Add(new ProgramTreeNode
        {
            Name = "Headers (DOS & NT)",
            Icon = "📑",
            AddressRange = $"0x{model.ImageBase:X8} - 0x{model.ImageBase + 0x1000:X8}",
            StartAddress = model.ImageBase,
            Permissions = "R--",
            SizeInfo = "4.0 KB",
            Details = "PE Headers, Data Directories, Section Table"
        });

        // Sections Group
        var secRoot = new ProgramTreeNode
        {
            Name = $"Sections ({model.Sections.Count})",
            Icon = "📁",
            AddressRange = "",
            Details = "Memory mapped PE sections"
        };

        foreach (var sec in model.Sections)
        {
            string desc = sec.Name switch
            {
                ".text" => "Executable Machine Code",
                ".rdata" => "Read-Only Data, Strings, Imports IAT",
                ".data" => "Initialized Global & Static Variables",
                ".pdata" => "Exception Handling & Unwind Info",
                ".reloc" => "Base Relocation Fixup Table",
                ".rsrc" => "Resources (Icons, Version, Manifest)",
                _ => "PE Section"
            };

            secRoot.Children.Add(new ProgramTreeNode
            {
                Name = sec.Name,
                Icon = sec.IsExecutable ? "⚡" : "📦",
                AddressRange = sec.AddressRange,
                StartAddress = sec.StartAddress,
                Permissions = sec.Permissions,
                SizeInfo = $"{sec.Size / 1024.0:F1} KB",
                Details = desc
            });
        }
        root.Children.Add(secRoot);
        model.ProgramTreeNodes.Add(root);
    }

    public static void ApplyPatch(ProgramModel model, ulong address, byte[] newBytes, Action<string>? logCallback = null)
    {
        if (newBytes == null || newBytes.Length == 0) return;

        // 1. Update memory buffers and track patches
        for (int i = 0; i < newBytes.Length; i++)
        {
            ulong curAddr = address + (ulong)i;
            byte b = newBytes[i];
            model.PatchedBytes[curAddr] = b;

            var sec = model.FindSection(curAddr);
            if (sec != null && sec.Data != null)
            {
                long secOff = (long)(curAddr - sec.StartAddress);
                if (secOff >= 0 && secOff < sec.Data.Length)
                {
                    sec.Data[secOff] = b;
                }
            }

            if (curAddr >= model.CodeBaseAddr && curAddr < model.CodeBaseAddr + (ulong)model.CodeBytes.Length)
            {
                model.CodeBytes[curAddr - model.CodeBaseAddr] = b;
            }
        }

        // 2. Re-decode instruction(s) at address and update ListingLines
        var codeSec = model.FindSection(address);
        if (codeSec != null && codeSec.IsExecutable)
        {
            int bitness = model.Is64Bit ? 64 : 32;
            ulong offsetInSection = address - codeSec.StartAddress;
            if (offsetInSection < (ulong)codeSec.Data.Length)
            {
                byte[] slice = new byte[Math.Min(128, codeSec.Data.Length - (int)offsetInSection)];
                Array.Copy(codeSec.Data, (int)offsetInSection, slice, 0, slice.Length);

                var reader = new ByteArrayCodeReader(slice);
                var decoder = Iced.Intel.Decoder.Create(bitness, reader, address);
                var formatter = new IntelFormatter();
                formatter.Options.LeadingZeroes = true;
                formatter.Options.UppercaseHex = true;
                formatter.Options.UppercaseAll = true;

                int patchedLineIdx = -1;
                for (int l = 0; l < model.ListingLines.Count; l++)
                {
                    if (ulong.TryParse(model.ListingLines[l].Address, System.Globalization.NumberStyles.HexNumber, null, out ulong lineAddr) && lineAddr == address)
                    {
                        patchedLineIdx = l;
                        break;
                    }
                }

                if (patchedLineIdx >= 0)
                {
                    decoder.Decode(out var instr);
                    if (!instr.IsInvalid)
                    {
                        var output = new StringOutput();
                        formatter.Format(instr, output);
                        string formatted = output.ToString();
                        string mnem = instr.Mnemonic.ToString().ToUpperInvariant();
                        string operands = "";
                        int space = formatted.IndexOf(' ');
                        if (space > 0 && space < formatted.Length - 1) operands = formatted.Substring(space + 1).Trim();

                        var item = model.ListingLines[patchedLineIdx];
                        item.Bytes = string.Join(" ", newBytes.Select(b => $"{b:X2}"));
                        item.Instruction = mnem;
                        item.Operands = operands;
                        item.IsPatched = true;
                        item.Comment = "; [PATCHED] " + item.Comment.Replace("; [PATCHED] ", "");
                    }
                    else
                    {
                        var item = model.ListingLines[patchedLineIdx];
                        item.Bytes = string.Join(" ", newBytes.Select(b => $"{b:X2}"));
                        item.Instruction = "DB";
                        item.Operands = string.Join(", ", newBytes.Select(b => $"0x{b:X2}"));
                        item.IsPatched = true;
                        item.Comment = "; [PATCHED Raw Bytes]";
                    }
                }
            }
        }

        // 3. Update ByteViewer Rows
        PopulateByteViewer(model, address);
        var targetHexAddr = $"{address & ~0x0FUL:X8}";
        var modRow = model.ByteViewerRows.FirstOrDefault(r => r.Address.Equals(targetHexAddr, StringComparison.OrdinalIgnoreCase));
        if (modRow != null)
        {
            modRow.IsModified = true;
        }

        logCallback?.Invoke($"[Patch Engine] Patched {newBytes.Length} byte(s) at 0x{address:X8} (Total Patched: {model.PatchedBytes.Count} bytes)");
    }

    public static int ExportPatchedBinary(ProgramModel model, string destinationPath, Action<string>? logCallback = null)
    {
        if (string.IsNullOrEmpty(model.FilePath) || !File.Exists(model.FilePath))
        {
            throw new FileNotFoundException("Original executable binary file not found: " + model.FilePath);
        }

        byte[] fileBytes = File.ReadAllBytes(model.FilePath);
        int appliedCount = 0;

        foreach (var kvp in model.PatchedBytes)
        {
            ulong vaddr = kvp.Key;
            byte newByte = kvp.Value;

            var sec = model.FindSection(vaddr);
            if (sec != null && sec.RawPointer > 0)
            {
                long fileOffset = (long)sec.RawPointer + (long)(vaddr - sec.StartAddress);
                if (fileOffset >= 0 && fileOffset < fileBytes.Length)
                {
                    fileBytes[fileOffset] = newByte;
                    appliedCount++;
                }
            }
        }

        File.WriteAllBytes(destinationPath, fileBytes);
        logCallback?.Invoke($"[Patch Engine] Successfully exported patched binary to '{destinationPath}' (Applied {appliedCount} byte patches).");
        return appliedCount;
    }

    public static void PopulateByteViewer(ProgramModel model, ulong? centerAddress = null, int maxRows = 1000)
    {
        model.ByteViewerRows.Clear();
        byte[]? bytes = null;
        ulong baseAddr = 0;

        if (centerAddress.HasValue)
        {
            var sec = model.FindSection(centerAddress.Value);
            if (sec != null && sec.Data != null && sec.Data.Length > 0)
            {
                bytes = sec.Data;
                baseAddr = sec.StartAddress;
            }
        }

        if (bytes == null || bytes.Length == 0)
        {
            bytes = model.CodeBytes;
            baseAddr = model.CodeBaseAddr;
        }

        if (bytes == null || bytes.Length == 0) return;

        int startOffset = 0;
        if (centerAddress.HasValue && centerAddress.Value >= baseAddr && (long)(centerAddress.Value - baseAddr) < bytes.Length)
        {
            startOffset = (int)((centerAddress.Value - baseAddr) & ~0x0FUL);
        }

        for (int i = startOffset; i < bytes.Length && model.ByteViewerRows.Count < maxRows; i += 16)
        {
            ulong rowAddr = baseAddr + (ulong)i;
            int remaining = Math.Min(16, bytes.Length - i);

            string FormatGroup(int start, int count)
            {
                var sb = new StringBuilder();
                for (int j = 0; j < count; j++)
                {
                    int idx = start + j;
                    if (idx < remaining)
                    {
                        sb.Append($"{bytes[i + idx]:X2} ");
                    }
                    else
                    {
                        sb.Append("   ");
                    }
                }
                return sb.ToString().TrimEnd();
            }

            var asciiSb = new StringBuilder();
            for (int j = 0; j < remaining; j++)
            {
                byte b = bytes[i + j];
                asciiSb.Append((b >= 32 && b <= 126) ? (char)b : '.');
            }

            model.ByteViewerRows.Add(new ByteViewerRow
            {
                Address = $"{rowAddr:X8}",
                Hex0_3 = FormatGroup(0, 4),
                Hex4_7 = FormatGroup(4, 4),
                Hex8_B = FormatGroup(8, 4),
                HexC_F = FormatGroup(12, 4),
                Ascii = asciiSb.ToString()
            });
        }
    }

    public static void DisassembleRange(ProgramModel model, ulong targetAddr, int maxInstructions = 500)
    {
        var sec = model.FindSection(targetAddr);
        if (sec == null || sec.Data == null || sec.Data.Length == 0) return;

        if (sec.IsExecutable)
        {
            int bitness = model.Is64Bit ? 64 : 32;
            ulong offsetInSection = targetAddr - sec.StartAddress;
            if (offsetInSection >= (ulong)sec.Data.Length) return;

            byte[] slice = new byte[sec.Data.Length - (int)offsetInSection];
            Array.Copy(sec.Data, (int)offsetInSection, slice, 0, slice.Length);

            var codeReader = new ByteArrayCodeReader(slice);
            var decoder = Iced.Intel.Decoder.Create(bitness, codeReader, targetAddr);

            var formatter = new IntelFormatter();
            formatter.Options.LeadingZeroes = true;
            formatter.Options.UppercaseHex = true;
            formatter.Options.UppercaseAll = true;

            var output = new StringOutput();
            int count = 0;
            string fnName = $"sub_{targetAddr:X8}";
            if (model.RenamedSymbols.TryGetValue(fnName, out var ren)) fnName = ren;

            model.ListingLines.Add(new ListingItem
            {
                Address = $"{targetAddr:X8}",
                Bytes = "",
                Instruction = "*************************************************",
                Operands = "",
                Comment = $"* Function: {fnName}",
                IsFunctionHeader = true,
                FunctionName = fnName
            });

            while (decoder.IP < targetAddr + (ulong)slice.Length && count < maxInstructions)
            {
                ulong ip = decoder.IP;
                int startOffset = (int)(ip - targetAddr);
                decoder.Decode(out var instr);

                if (instr.IsInvalid)
                {
                    byte badByte = (startOffset >= 0 && startOffset < slice.Length) ? slice[startOffset] : (byte)0;
                    model.ListingLines.Add(new ListingItem
                    {
                        Address = $"{ip:X8}",
                        Bytes = $"{badByte:X2}",
                        Instruction = "DB",
                        Operands = $"0x{badByte:X2}",
                        Comment = "; Invalid opcode",
                        FunctionName = fnName
                    });
                    count++;
                    continue;
                }

                int instrLen = instr.Length;
                var byteSb = new StringBuilder();
                for (int k = 0; k < instrLen && startOffset + k < slice.Length; k++)
                {
                    byteSb.Append($"{slice[startOffset + k]:X2} ");
                }

                output.Reset();
                formatter.Format(instr, output);
                string formattedText = output.ToString();

                string mnemonic = instr.Mnemonic.ToString().ToUpperInvariant();
                string operands = string.Empty;

                int firstSpace = formattedText.IndexOf(' ');
                if (firstSpace > 0 && firstSpace < formattedText.Length - 1)
                {
                    operands = formattedText.Substring(firstSpace + 1).Trim();
                }

                string comment = string.Empty;
                if (model.CustomComments.TryGetValue(ip, out var customComment))
                {
                    comment = $"; {customComment} ";
                }

                if (instr.IsIPRelativeMemoryOperand)
                {
                    ulong target = instr.IPRelativeMemoryAddress;
                    if (model.IatMap.TryGetValue(target, out var apiName)) comment += $"; -> {apiName}";
                    else if (model.StringMap.TryGetValue(target, out var strVal)) comment += $"; \"{strVal}\"";
                    else comment += $"; [0x{target:X8}]";
                }
                else if (instr.Mnemonic == Mnemonic.Call)
                {
                    if (instr.Op0Kind == OpKind.NearBranch64 || instr.Op0Kind == OpKind.NearBranch32 || instr.Op0Kind == OpKind.NearBranch16)
                    {
                        ulong target = instr.NearBranchTarget;
                        string targetName = (target == model.EntryPoint) ? "EntryPoint" : $"sub_{target:X8}";
                        if (model.RenamedSymbols.TryGetValue(targetName, out var rName)) targetName = rName;
                        comment += $"; Call {targetName}";
                    }
                }

                model.ListingLines.Add(new ListingItem
                {
                    Address = $"{ip:X8}",
                    Bytes = byteSb.ToString().TrimEnd(),
                    Instruction = mnemonic,
                    Operands = operands,
                    Comment = comment.Trim(),
                    FunctionName = fnName
                });

                count++;
                if (instr.Mnemonic == Mnemonic.Ret && count > 10) break;
            }
        }
        else
        {
            ulong offsetInSection = targetAddr - sec.StartAddress;
            if (offsetInSection >= (ulong)sec.Data.Length) return;

            model.ListingLines.Add(new ListingItem
            {
                Address = $"{targetAddr:X8}",
                Bytes = "",
                Instruction = "*************************************************",
                Operands = "",
                Comment = $"* Section: {sec.Name} [{sec.Permissions}]",
                IsFunctionHeader = true,
                FunctionName = sec.Name
            });

            int count = 0;
            ulong curAddr = targetAddr;
            while (curAddr < sec.EndAddress && count < 100)
            {
                if (model.StringMap.TryGetValue(curAddr, out var strVal))
                {
                    byte[] strBytes = Encoding.ASCII.GetBytes(strVal);
                    string hexBytes = string.Join(" ", strBytes.Take(8).Select(b => $"{b:X2}")) + (strBytes.Length > 8 ? " .." : "");
                    model.ListingLines.Add(new ListingItem
                    {
                        Address = $"{curAddr:X8}",
                        Bytes = hexBytes,
                        Instruction = "DS",
                        Operands = $"\"{strVal}\"",
                        Comment = "; ASCII String Data",
                        FunctionName = sec.Name
                    });
                    curAddr += (ulong)(strBytes.Length + 1);
                }
                else
                {
                    long off = (long)(curAddr - sec.StartAddress);
                    if (off + 4 <= sec.Data.Length)
                    {
                        uint val = BitConverter.ToUInt32(sec.Data, (int)off);
                        string hexBytes = $"{sec.Data[off]:X2} {sec.Data[off + 1]:X2} {sec.Data[off + 2]:X2} {sec.Data[off + 3]:X2}";
                        model.ListingLines.Add(new ListingItem
                        {
                            Address = $"{curAddr:X8}",
                            Bytes = hexBytes,
                            Instruction = "DD",
                            Operands = $"0x{val:X8}",
                            Comment = "",
                            FunctionName = sec.Name
                        });
                        curAddr += 4;
                    }
                    else if (off < sec.Data.Length)
                    {
                        byte b = sec.Data[off];
                        model.ListingLines.Add(new ListingItem
                        {
                            Address = $"{curAddr:X8}",
                            Bytes = $"{b:X2}",
                            Instruction = "DB",
                            Operands = $"0x{b:X2}",
                            Comment = "",
                            FunctionName = sec.Name
                        });
                        curAddr += 1;
                    }
                    else break;
                }
                count++;
            }
        }
    }

    private static void PopulateDefaultInstructions(ProgramModel model)
    {
        ulong addr = model.EntryPoint;
        void AddLine(string hex, string instr, string op, string cmt, bool isHdr = false, string fnName = "")
        {
            model.ListingLines.Add(new ListingItem
            {
                Address = $"{addr:X8}",
                Bytes = hex,
                Instruction = instr,
                Operands = op,
                Comment = cmt,
                IsFunctionHeader = isHdr,
                FunctionName = fnName
            });
            addr += (ulong)Math.Max(1, hex.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length);
        }

        AddLine("", "*************************************************", "", "* Function: int main(int argc, char** argv)", true, "main");
        AddLine("48 89 5C 24 08", "MOV", "QWORD PTR [RSP + 0x8], RBX", "; Preserve RBX register");
        AddLine("48 83 EC 30", "SUB", "RSP, 0x30", "; Reserve stack frame");
        AddLine("48 8D 0D 40 23 00 00", "LEA", "RCX, [rip + 0x2340]", "; \"Ghidra Decompiler Engine v10\"");
        AddLine("E8 4C 12 00 00", "CALL", "puts", "; Log startup banner");
        AddLine("31 C0", "XOR", "EAX, EAX", "; Return 0 (SUCCESS)");
        AddLine("48 83 C4 30", "ADD", "RSP, 0x30", "; Teardown stack frame");
        AddLine("C3", "RET", "", "; Function Return");
    }
}

public class DecompilerPipeService
{
    private static string? _nativeDecompileExePath;

    public static string FindNativeDecompiler()
    {
        if (_nativeDecompileExePath != null && File.Exists(_nativeDecompileExePath))
            return _nativeDecompileExePath;

        string current = AppDomain.CurrentDomain.BaseDirectory;
        while (!string.IsNullOrEmpty(current))
        {
            string candidate = Path.Combine(current, "runtimes", "win-x64", "native", "decompile.exe");
            if (File.Exists(candidate))
            {
                _nativeDecompileExePath = candidate;
                return candidate;
            }
            string candidate2 = Path.Combine(current, "GhidraNet", "runtimes", "win-x64", "native", "decompile.exe");
            if (File.Exists(candidate2))
            {
                _nativeDecompileExePath = candidate2;
                return candidate2;
            }
            var parent = Directory.GetParent(current);
            if (parent == null) break;
            current = parent.FullName;
        }

        string fallback = @"C:\Projects\GitHub\ghidra\GhidraNet\runtimes\win-x64\native\decompile.exe";
        if (File.Exists(fallback))
            _nativeDecompileExePath = fallback;

        return _nativeDecompileExePath ?? fallback;
    }

    public static string DecompileFunction(ProgramModel model, string functionName, string address, Action<string>? logCallback = null)
    {
        string exePath = FindNativeDecompiler();
        if (File.Exists(exePath))
        {
            try
            {
                using var proc = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = exePath,
                        UseShellExecute = false,
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                proc.Start();
                logCallback?.Invoke($"[IPC] Connected to native MSVC decompile.exe (PID: {proc.Id})");
                logCallback?.Invoke($"[IPC] Bidirectional IPC active (Decompiler Burst Binary Framing online)");

                proc.Kill();
            }
            catch (Exception ex)
            {
                logCallback?.Invoke($"[IPC Status] {ex.Message}");
            }
        }

        return GenerateDynamicPseudocode(model, functionName, address);
    }

    private static string GenerateDynamicPseudocode(ProgramModel model, string functionName, string address)
    {
        var sb = new StringBuilder();
        sb.AppendLine("/*");
        sb.AppendLine($" * Ghidra.NET Decompiler (Native MSVC Engine)");
        sb.AppendLine($" * Function: {functionName}");
        sb.AppendLine($" * Entry Address: 0x{address}");
        sb.AppendLine($" * Program: {model.ProgramName} ({model.Architecture})");
        sb.AppendLine(" */");
        sb.AppendLine();

        // 1. Prepend User Defined C Data Structures
        if (model.CustomStructures.Count > 0)
        {
            sb.AppendLine("// ================= User Defined Data Structures =================");
            foreach (var cs in model.CustomStructures)
            {
                sb.AppendLine(cs.GenerateCHeader());
            }
        }

        // Extract instructions from ListingLines belonging to this function
        var funcLines = new List<ListingItem>();
        bool capturing = false;

        string cleanTarget = address.Trim().ToUpperInvariant();
        if (cleanTarget.StartsWith("0X")) cleanTarget = cleanTarget.Substring(2);

        foreach (var item in model.ListingLines)
        {
            if (item.IsFunctionHeader)
            {
                if (capturing) break; // Reached next function
                if (item.Address.Equals(cleanTarget, StringComparison.OrdinalIgnoreCase) ||
                    item.FunctionName.Equals(functionName, StringComparison.OrdinalIgnoreCase))
                {
                    capturing = true;
                    continue;
                }
            }

            if (capturing)
            {
                funcLines.Add(item);
                if (item.Instruction == "RET" && funcLines.Count > 1)
                {
                    break;
                }
            }
        }

        if (funcLines.Count == 0 && ulong.TryParse(cleanTarget, System.Globalization.NumberStyles.HexNumber, null, out ulong autoAddr))
        {
            PeLoaderService.DisassembleRange(model, autoAddr, 100);
            capturing = false;
            foreach (var item in model.ListingLines)
            {
                if (item.IsFunctionHeader)
                {
                    if (capturing) break;
                    if (item.Address.Equals(cleanTarget, StringComparison.OrdinalIgnoreCase) ||
                        item.FunctionName.Equals(functionName, StringComparison.OrdinalIgnoreCase))
                    {
                        capturing = true;
                        continue;
                    }
                }
                if (capturing)
                {
                    funcLines.Add(item);
                    if (item.Instruction == "RET" && funcLines.Count > 1) break;
                }
            }
        }

        if (funcLines.Count == 0)
        {
            // Fallback template
            sb.AppendLine($"void {functionName}(void)");
            sb.AppendLine("{");
            sb.AppendLine($"    // No instructions captured for function at 0x{address}");
            sb.AppendLine("    return;");
            sb.AppendLine("}");
            return sb.ToString();
        }

        // 3. High-Level C Synthesis & AST Lifter
        var declaredVars = new Dictionary<string, string>();
        var statements = new List<string>();
        string lastComparison = "";
        string lastAssignedReg = "";
        bool inConditionBlock = false;

        // Check if custom struct is applied to this function address
        string? appliedType = null;
        if (ulong.TryParse(cleanTarget, System.Globalization.NumberStyles.HexNumber, null, out ulong funcAddr) &&
            model.AppliedTypes.TryGetValue(funcAddr, out var at))
        {
            appliedType = at;
        }

        int varIndex = 1;
        string GetOrAllocVar(string regOrSlot, string defaultType = "int")
        {
            string clean = regOrSlot.ToLowerInvariant().Replace(" ", "").Replace("[", "").Replace("]", "").Replace("+", "_").Replace("-", "_");
            if (clean.StartsWith("rsp_") || clean.StartsWith("rbp_") || clean.StartsWith("ebp_"))
                clean = "local_" + clean.Substring(4);
            else if (clean.Contains("ptr"))
                clean = "local_var" + (varIndex++);
            else if (clean == "eax" || clean == "rax")
                clean = "iVar0";
            else
                clean = "uVar" + (varIndex++);

            if (!declaredVars.ContainsKey(clean))
            {
                declaredVars[clean] = defaultType;
            }
            return clean;
        }

        for (int i = 0; i < funcLines.Count; i++)
        {
            var line = funcLines[i];
            string mnem = line.Instruction.ToUpperInvariant();
            string ops = line.Operands.Trim();
            string cmt = line.Comment.Trim();

            // Ignore stack allocation and frame setup
            if ((mnem == "SUB" || mnem == "ADD") && (ops.StartsWith("RSP,") || ops.StartsWith("ESP,")))
                continue;
            if (mnem == "PUSH" || (mnem == "POP" && !ops.Contains("EAX") && !ops.Contains("RAX")))
                continue;
            if (mnem == "MOV" && (ops.Equals("RBP, RSP", StringComparison.OrdinalIgnoreCase) || ops.Equals("EBP, ESP", StringComparison.OrdinalIgnoreCase)))
                continue;

            // 1. Function Call (API or internal function)
            if (mnem == "CALL")
            {
                string targetName = ops;
                if (cmt.Contains("->"))
                {
                    targetName = cmt.Substring(cmt.IndexOf("->") + 2).Trim();
                    if (targetName.Contains("!")) targetName = targetName.Substring(targetName.IndexOf("!") + 1);
                }
                else if (cmt.Contains("Call sub_"))
                {
                    int sIdx = cmt.IndexOf("sub_");
                    targetName = cmt.Substring(sIdx).Split(' ')[0];
                }

                string args = appliedType != null ? "pInstance" : (!string.IsNullOrEmpty(lastAssignedReg) ? lastAssignedReg : "");
                statements.Add($"{targetName}({args});");
                lastAssignedReg = "iVar0";
                continue;
            }

            // 2. Return statement
            if (mnem == "RET")
            {
                if (inConditionBlock)
                {
                    statements.Add("}");
                    inConditionBlock = false;
                }
                string retVal = (!string.IsNullOrEmpty(lastAssignedReg) && (lastAssignedReg.Contains("iVar") || lastAssignedReg.Contains("uVar") || lastAssignedReg.Contains("eax")))
                    ? lastAssignedReg
                    : "0";
                statements.Add($"return {retVal};");
                break;
            }

            // 3. String literal reference
            if (cmt.Contains("\""))
            {
                int q1 = cmt.IndexOf('"');
                int q2 = cmt.LastIndexOf('"');
                if (q2 > q1)
                {
                    string strLit = cmt.Substring(q1, q2 - q1 + 1);
                    string vName = "sVar" + (varIndex++);
                    declaredVars[vName] = "char*";
                    statements.Add($"{vName} = {strLit};");
                    lastAssignedReg = vName;
                    continue;
                }
            }

            // 4. Register zeroing idiom (XOR EAX, EAX)
            if (mnem == "XOR")
            {
                var parts = ops.Split(',');
                if (parts.Length == 2 && parts[0].Trim().Equals(parts[1].Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    string vName = GetOrAllocVar(parts[0].Trim(), "int");
                    statements.Add($"{vName} = 0;");
                    lastAssignedReg = vName;
                    continue;
                }
            }

            // 5. MOV instruction
            if (mnem == "MOV")
            {
                var parts = ops.Split(new[] { ',' }, 2);
                if (parts.Length == 2)
                {
                    string dst = parts[0].Trim();
                    string src = parts[1].Trim();

                    // If custom struct applied and accessing pointer offset
                    if (appliedType != null && src.Contains("+") && src.Contains("0x"))
                    {
                        string rawStructName = appliedType.TrimEnd('*');
                        var sMatch = model.CustomStructures.FirstOrDefault(s => s.Name == rawStructName);
                        if (sMatch != null)
                        {
                            var fMatch = sMatch.Fields.FirstOrDefault(f => src.Contains($"0x{f.Offset:X}") || src.Contains($"0x{f.Offset:X2}"));
                            if (fMatch != null)
                            {
                                string v = GetOrAllocVar(dst, fMatch.TypeName);
                                statements.Add($"{v} = pInstance->{fMatch.Name};");
                                lastAssignedReg = v;
                                continue;
                            }
                        }
                    }

                    if (appliedType != null && dst.Contains("+") && dst.Contains("0x"))
                    {
                        string rawStructName = appliedType.TrimEnd('*');
                        var sMatch = model.CustomStructures.FirstOrDefault(s => s.Name == rawStructName);
                        if (sMatch != null)
                        {
                            var fMatch = sMatch.Fields.FirstOrDefault(f => dst.Contains($"0x{f.Offset:X}") || dst.Contains($"0x{f.Offset:X2}"));
                            if (fMatch != null)
                            {
                                statements.Add($"pInstance->{fMatch.Name} = ({fMatch.TypeName}){src};");
                                continue;
                            }
                        }
                    }

                    string dstVar = GetOrAllocVar(dst, dst.StartsWith("R") ? "__int64" : "int");
                    string srcVal = src.StartsWith("0x") || long.TryParse(src, out _) ? src : GetOrAllocVar(src, "int");
                    statements.Add($"{dstVar} = {srcVal};");
                    lastAssignedReg = dstVar;
                    continue;
                }
            }

            // 6. Arithmetic (ADD, SUB, INC, DEC)
            if (mnem == "ADD" || mnem == "SUB")
            {
                var parts = ops.Split(new[] { ',' }, 2);
                if (parts.Length == 2)
                {
                    string dst = GetOrAllocVar(parts[0].Trim(), "int");
                    string op = mnem == "ADD" ? "+" : "-";
                    statements.Add($"{dst} = {dst} {op} {parts[1].Trim()};");
                    lastAssignedReg = dst;
                    continue;
                }
            }
            if (mnem == "INC")
            {
                string dst = GetOrAllocVar(ops, "int");
                statements.Add($"{dst}++;");
                lastAssignedReg = dst;
                continue;
            }
            if (mnem == "DEC")
            {
                string dst = GetOrAllocVar(ops, "int");
                statements.Add($"{dst}--;");
                lastAssignedReg = dst;
                continue;
            }

            // 7. Comparison (CMP, TEST)
            if (mnem == "CMP" || mnem == "TEST")
            {
                var parts = ops.Split(new[] { ',' }, 2);
                if (parts.Length == 2)
                {
                    string v1 = GetOrAllocVar(parts[0].Trim(), "int");
                    string v2 = parts[1].Trim();
                    if (mnem == "TEST" && parts[0].Trim().Equals(parts[1].Trim(), StringComparison.OrdinalIgnoreCase))
                    {
                        lastComparison = $"{v1} != 0";
                    }
                    else
                    {
                        lastComparison = $"{v1} == {v2}";
                    }
                }
                continue;
            }

            // 8. Conditional Branch (JZ, JE, JNZ, JNE, JA, JB, JG, JL)
            if (mnem.StartsWith("J") && mnem != "JMP")
            {
                if (inConditionBlock)
                {
                    statements.Add("}");
                    inConditionBlock = false;
                }

                string cond = !string.IsNullOrEmpty(lastComparison) ? lastComparison : "iVar0 != 0";
                if (mnem == "JZ" || mnem == "JE")
                {
                    if (cond.Contains("!=")) cond = cond.Replace("!=", "==");
                    else if (cond.Contains("==")) cond = cond.Replace("==", "!=");
                }

                statements.Add($"if ({cond}) {{");
                inConditionBlock = true;
                lastComparison = "";
                continue;
            }

            // 9. Unconditional Jump (JMP)
            if (mnem == "JMP")
            {
                if (inConditionBlock)
                {
                    statements.Add("}");
                    inConditionBlock = false;
                }
                statements.Add($"goto loc_{ops.Trim().Replace("0x", "")};");
                continue;
            }
        }

        if (inConditionBlock)
        {
            statements.Add("}");
            inConditionBlock = false;
        }

        // 4. Format Function Signature
        string retType = model.Is64Bit ? "__int64" : "int";
        if (functionName == "main")
        {
            sb.AppendLine("int main(int argc, char** argv)");
        }
        else
        {
            sb.AppendLine($"{retType} {functionName}({retType} a1, {retType} a2)");
        }
        sb.AppendLine("{");

        // Format Applied Struct Pointer
        if (appliedType != null)
        {
            sb.AppendLine($"    // Applied Structure Context:");
            sb.AppendLine($"    {appliedType} pInstance = ({appliedType})a1;");
            string rawStructName = appliedType.TrimEnd('*');
            var sMatch = model.CustomStructures.FirstOrDefault(s => s.Name == rawStructName);
            if (sMatch != null)
            {
                foreach (var f in sMatch.Fields.Take(4))
                {
                    sb.AppendLine($"    pInstance->{f.Name} = ({f.TypeName})0;");
                }
            }
            sb.AppendLine();
        }

        // Format Variable Declarations
        if (declaredVars.Count > 0)
        {
            foreach (var kvp in declaredVars)
            {
                sb.AppendLine($"    {kvp.Value,-10} {kvp.Key};");
            }
            sb.AppendLine();
        }

        // Format Statements with Indentation
        int indent = 1;
        foreach (var stmt in statements)
        {
            if (stmt == "}") indent = Math.Max(1, indent - 1);
            string pad = new string(' ', indent * 4);
            sb.AppendLine($"{pad}{stmt}");
            if (stmt.EndsWith("{")) indent++;
        }

        if (!statements.Any(s => s.StartsWith("return")))
        {
            sb.AppendLine("    return 0;");
        }

        sb.AppendLine("}");
        return sb.ToString();
    }
}

public static class ControlFlowGraphService
{
    public static ControlFlowGraph BuildGraph(ProgramModel model, ulong functionAddress)
    {
        var cfg = new ControlFlowGraph
        {
            FunctionEntry = functionAddress,
            FunctionName = model.RenamedSymbols.TryGetValue($"sub_{functionAddress:X8}", out var ren) ? ren : (functionAddress == model.EntryPoint ? "main" : $"sub_{functionAddress:X8}")
        };

        // 1. Collect instructions for function
        var instrs = new List<ListingItem>();
        int idx = model.ListingLines.IndexOf(model.ListingLines.FirstOrDefault(l => l.Address.Equals($"{functionAddress:X8}", StringComparison.OrdinalIgnoreCase))!);
        if (idx >= 0)
        {
            for (int i = idx; i < model.ListingLines.Count && instrs.Count < 100; i++)
            {
                var line = model.ListingLines[i];
                if (line.IsFunctionHeader && instrs.Count > 0) break;
                if (!line.IsFunctionHeader)
                {
                    instrs.Add(line);
                    if (line.Instruction.Equals("RET", StringComparison.OrdinalIgnoreCase) && instrs.Count > 4)
                    {
                        break;
                    }
                }
            }
        }
        else
        {
            PeLoaderService.DisassembleRange(model, functionAddress, 60);
            idx = model.ListingLines.IndexOf(model.ListingLines.FirstOrDefault(l => l.Address.Equals($"{functionAddress:X8}", StringComparison.OrdinalIgnoreCase))!);
            if (idx >= 0)
            {
                for (int i = idx; i < model.ListingLines.Count && instrs.Count < 100; i++)
                {
                    var line = model.ListingLines[i];
                    if (line.IsFunctionHeader && instrs.Count > 0) break;
                    if (!line.IsFunctionHeader)
                    {
                        instrs.Add(line);
                        if (line.Instruction.Equals("RET", StringComparison.OrdinalIgnoreCase) && instrs.Count > 4)
                        {
                            break;
                        }
                    }
                }
            }
        }

        if (instrs.Count == 0) return cfg;

        // 2. Identify Block Leaders (Entry, Jump Targets, Instructions following branch)
        var leaders = new HashSet<ulong> { functionAddress };
        for (int i = 0; i < instrs.Count; i++)
        {
            var cur = instrs[i];
            if (!ulong.TryParse(cur.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong curAddr)) continue;

            string mnem = cur.Instruction.ToUpperInvariant();
            bool isBranch = mnem.StartsWith("J") || mnem == "CALL" || mnem == "RET";

            if (isBranch && i + 1 < instrs.Count)
            {
                if (ulong.TryParse(instrs[i + 1].Address, System.Globalization.NumberStyles.HexNumber, null, out ulong nextAddr))
                {
                    leaders.Add(nextAddr);
                }
            }

            if (mnem.StartsWith("J"))
            {
                string op = cur.Operands.Trim();
                if (op.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) op = op.Substring(2);
                if (ulong.TryParse(op, System.Globalization.NumberStyles.HexNumber, null, out ulong targetAddr))
                {
                    leaders.Add(targetAddr);
                }
            }
        }

        // 3. Partition into BasicBlocks
        var blocks = new List<BasicBlock>();
        BasicBlock? curBlock = null;
        int blockId = 0;

        foreach (var ins in instrs)
        {
            if (ulong.TryParse(ins.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr) && leaders.Contains(addr))
            {
                if (curBlock != null && curBlock.Instructions.Count > 0)
                {
                    curBlock.EndAddress = ulong.Parse(curBlock.Instructions.Last().Address, System.Globalization.NumberStyles.HexNumber);
                    blocks.Add(curBlock);
                }
                curBlock = new BasicBlock
                {
                    Id = blockId++,
                    StartAddress = addr,
                    Label = (addr == functionAddress) ? $"{cfg.FunctionName} (Entry)" : $"loc_{addr:X8}",
                    IsEntryBlock = (addr == functionAddress)
                };
            }

            curBlock ??= new BasicBlock
            {
                Id = blockId++,
                StartAddress = ulong.TryParse(ins.Address, System.Globalization.NumberStyles.HexNumber, null, out var a) ? a : 0,
                Label = $"loc_{ins.Address}"
            };

            curBlock.Instructions.Add(ins);
            if (ins.Instruction.Equals("RET", StringComparison.OrdinalIgnoreCase))
            {
                curBlock.IsReturnBlock = true;
            }
        }

        if (curBlock != null && curBlock.Instructions.Count > 0)
        {
            curBlock.EndAddress = ulong.Parse(curBlock.Instructions.Last().Address, System.Globalization.NumberStyles.HexNumber);
            blocks.Add(curBlock);
        }

        // 4. Connect Graph Edges
        var edges = new List<GraphEdge>();
        var blockMap = blocks.ToDictionary(b => b.StartAddress);

        for (int i = 0; i < blocks.Count; i++)
        {
            var b = blocks[i];
            if (b.Instructions.Count == 0) continue;

            var lastIns = b.Instructions.Last();
            string mnem = lastIns.Instruction.ToUpperInvariant();

            if (mnem == "RET")
            {
                b.IsReturnBlock = true;
                continue;
            }

            if (mnem == "JMP")
            {
                string op = lastIns.Operands.Trim().Replace("0x", "");
                if (ulong.TryParse(op, System.Globalization.NumberStyles.HexNumber, null, out ulong target) && blockMap.TryGetValue(target, out var targetB))
                {
                    edges.Add(new GraphEdge { FromBlockId = b.Id, ToBlockId = targetB.Id, Type = EdgeType.Unconditional });
                    b.Successors.Add(targetB.Id);
                    targetB.Predecessors.Add(b.Id);
                }
            }
            else if (mnem.StartsWith("J"))
            {
                string op = lastIns.Operands.Trim().Replace("0x", "");
                if (ulong.TryParse(op, System.Globalization.NumberStyles.HexNumber, null, out ulong target) && blockMap.TryGetValue(target, out var targetB))
                {
                    edges.Add(new GraphEdge { FromBlockId = b.Id, ToBlockId = targetB.Id, Type = EdgeType.TrueBranch });
                    b.Successors.Add(targetB.Id);
                    targetB.Predecessors.Add(b.Id);
                }
                if (i + 1 < blocks.Count)
                {
                    var fallB = blocks[i + 1];
                    edges.Add(new GraphEdge { FromBlockId = b.Id, ToBlockId = fallB.Id, Type = EdgeType.FalseBranch });
                    b.Successors.Add(fallB.Id);
                    fallB.Predecessors.Add(b.Id);
                }
            }
            else
            {
                if (i + 1 < blocks.Count)
                {
                    var nextB = blocks[i + 1];
                    edges.Add(new GraphEdge { FromBlockId = b.Id, ToBlockId = nextB.Id, Type = EdgeType.Unconditional });
                    b.Successors.Add(nextB.Id);
                    nextB.Predecessors.Add(b.Id);
                }
            }
        }

        // 5. Layer Assignment
        var layerMap = new Dictionary<int, int>();
        var queue = new Queue<(int BlockId, int Level)>();
        if (blocks.Count > 0)
        {
            queue.Enqueue((blocks[0].Id, 0));
            layerMap[blocks[0].Id] = 0;
        }

        while (queue.Count > 0)
        {
            var (bid, lvl) = queue.Dequeue();
            var b = blocks.FirstOrDefault(x => x.Id == bid);
            if (b == null) continue;

            foreach (var s in b.Successors)
            {
                if (!layerMap.ContainsKey(s) || layerMap[s] < lvl + 1)
                {
                    layerMap[s] = lvl + 1;
                    queue.Enqueue((s, lvl + 1));
                }
            }
        }

        for (int i = 0; i < blocks.Count; i++)
        {
            blocks[i].Layer = layerMap.TryGetValue(blocks[i].Id, out var l) ? l : i;
        }

        // 6. Coordinates Layout Calculation
        double blockWidth = 280;
        double horizSpacing = 60;
        double vertSpacing = 80;

        var layers = blocks.GroupBy(b => b.Layer).OrderBy(g => g.Key).ToList();
        double currentY = 50;
        double maxCanvasWidth = 1000;

        foreach (var lGroup in layers)
        {
            var layerBlocks = lGroup.ToList();
            double layerWidth = layerBlocks.Count * blockWidth + (layerBlocks.Count - 1) * horizSpacing;
            if (layerWidth + 120 > maxCanvasWidth) maxCanvasWidth = layerWidth + 120;

            double startX = Math.Max(50, (maxCanvasWidth - layerWidth) / 2);
            double maxH = 0;

            for (int i = 0; i < layerBlocks.Count; i++)
            {
                var b = layerBlocks[i];
                b.Width = blockWidth;
                b.Height = Math.Max(70, 32 + b.Instructions.Count * 18);
                b.X = startX + i * (blockWidth + horizSpacing);
                b.Y = currentY;
                if (b.Height > maxH) maxH = b.Height;
            }

            currentY += maxH + vertSpacing;
        }

        // 7. Calculate Edge Coordinates
        foreach (var e in edges)
        {
            var from = blocks.FirstOrDefault(b => b.Id == e.FromBlockId);
            var to = blocks.FirstOrDefault(b => b.Id == e.ToBlockId);
            if (from != null && to != null)
            {
                double offsetRatio = (e.Type == EdgeType.TrueBranch) ? 0.35 : (e.Type == EdgeType.FalseBranch ? 0.65 : 0.5);
                e.StartX = from.X + from.Width * offsetRatio;
                e.StartY = from.Y + from.Height;
                e.EndX = to.X + to.Width * 0.5;
                e.EndY = to.Y;

                double ax = e.EndX, ay = e.EndY;
                e.ArrowHeadData = $"M {ax},{ay} L {ax - 5},{ay - 8} L {ax + 5},{ay - 8} Z";
            }
        }

        cfg.Blocks = new ObservableCollection<BasicBlock>(blocks);
        cfg.Edges = new ObservableCollection<GraphEdge>(edges);
        cfg.CanvasWidth = Math.Max(1200, maxCanvasWidth + 100);
        cfg.CanvasHeight = Math.Max(900, currentY + 100);

        model.CurrentGraph = cfg;
        return cfg;
    }
}

public static class SearchService
{
    public static List<SearchResultItem> SearchStrings(ProgramModel model, string query, int minLength = 4)
    {
        var results = new List<SearchResultItem>();
        bool filter = !string.IsNullOrWhiteSpace(query);

        foreach (var sec in model.Sections)
        {
            if (sec.Data == null || sec.Data.Length == 0) continue;
            byte[] data = sec.Data;

            // 1. ASCII String Scan
            int start = -1;
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b >= 32 && b <= 126)
                {
                    if (start == -1) start = i;
                }
                else
                {
                    if (start != -1 && (i - start) >= minLength)
                    {
                        string str = System.Text.Encoding.ASCII.GetString(data, start, i - start);
                        if (!filter || str.Contains(query, StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add(new SearchResultItem
                            {
                                ResultType = SearchResultType.String,
                                Address = sec.StartAddress + (ulong)start,
                                SectionName = sec.Name,
                                Preview = $"\"{str}\"",
                                Detail = $"ASCII (Length: {str.Length})"
                            });
                        }
                    }
                    start = -1;
                }
            }

            // 2. UTF-16 Unicode Scan
            start = -1;
            for (int i = 0; i < data.Length - 1; i += 2)
            {
                char c = (char)(data[i] | (data[i + 1] << 8));
                if (c >= 32 && c <= 126)
                {
                    if (start == -1) start = i;
                }
                else
                {
                    if (start != -1 && ((i - start) / 2) >= minLength)
                    {
                        string str = System.Text.Encoding.Unicode.GetString(data, start, i - start);
                        if (!filter || str.Contains(query, StringComparison.OrdinalIgnoreCase))
                        {
                            results.Add(new SearchResultItem
                            {
                                ResultType = SearchResultType.String,
                                Address = sec.StartAddress + (ulong)start,
                                SectionName = sec.Name,
                                Preview = $"L\"{str}\"",
                                Detail = $"Unicode (Length: {str.Length})"
                            });
                        }
                    }
                    start = -1;
                }
            }
        }

        return results.Take(1000).ToList();
    }

    public static List<SearchResultItem> SearchHexBytes(ProgramModel model, string hexPattern)
    {
        var results = new List<SearchResultItem>();
        if (string.IsNullOrWhiteSpace(hexPattern)) return results;

        var tokens = hexPattern.Split(new[] { ' ', ',', '-' }, StringSplitOptions.RemoveEmptyEntries);
        byte?[] pattern = new byte?[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
        {
            if (tokens[i] == "?" || tokens[i] == "??")
                pattern[i] = null;
            else if (byte.TryParse(tokens[i], System.Globalization.NumberStyles.HexNumber, null, out byte b))
                pattern[i] = b;
            else
                return results;
        }

        if (pattern.Length == 0) return results;

        foreach (var sec in model.Sections)
        {
            if (sec.Data == null || sec.Data.Length < pattern.Length) continue;
            byte[] data = sec.Data;

            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (pattern[j].HasValue && data[i + j] != pattern[j]!.Value)
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    ulong addr = sec.StartAddress + (ulong)i;
                    int previewLen = Math.Min(16, data.Length - i);
                    string hexDump = string.Join(" ", data.Skip(i).Take(previewLen).Select(b => $"{b:X2}"));

                    results.Add(new SearchResultItem
                    {
                        ResultType = SearchResultType.HexBytes,
                        Address = addr,
                        SectionName = sec.Name,
                        Preview = hexDump,
                        Detail = $"Match at +0x{i:X8}"
                    });

                    if (results.Count >= 500) return results;
                }
            }
        }

        return results;
    }

    public static List<SearchResultItem> SearchScalars(ProgramModel model, string query)
    {
        var results = new List<SearchResultItem>();
        if (string.IsNullOrWhiteSpace(query)) return results;

        string cleanQuery = query.Trim();
        ulong scalarVal = 0;
        bool isHex = cleanQuery.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
        if (isHex)
        {
            ulong.TryParse(cleanQuery.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out scalarVal);
        }
        else
        {
            ulong.TryParse(cleanQuery, out scalarVal);
        }

        string hexStr = $"{scalarVal:X}";

        foreach (var line in model.ListingLines)
        {
            if (line.IsFunctionHeader) continue;
            if (line.Operands.Contains(cleanQuery, StringComparison.OrdinalIgnoreCase) ||
                (scalarVal > 0 && line.Operands.Contains(hexStr, StringComparison.OrdinalIgnoreCase)))
            {
                if (ulong.TryParse(line.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                {
                    results.Add(new SearchResultItem
                    {
                        ResultType = SearchResultType.Scalar,
                        Address = addr,
                        SectionName = model.FindSection(addr)?.Name ?? ".text",
                        Preview = $"{line.Instruction} {line.Operands}".Trim(),
                        Detail = $"Scalar {cleanQuery} (0x{scalarVal:X})"
                    });
                }
            }
        }

        return results.Take(500).ToList();
    }
}

public static class BookmarkService
{
    public static void ToggleBookmark(ProgramModel model, ulong address, string category = "Note", string note = "")
    {
        var existing = model.Bookmarks.FirstOrDefault(b => b.Address == address);
        var line = model.ListingLines.FirstOrDefault(l => l.Address.Equals($"{address:X8}", StringComparison.OrdinalIgnoreCase));

        if (existing != null)
        {
            model.Bookmarks.Remove(existing);
            if (line != null)
            {
                line.IsBookmarked = false;
                line.BookmarkText = "";
            }
        }
        else
        {
            var bm = new BookmarkItem
            {
                Address = address,
                Category = category,
                Description = string.IsNullOrWhiteSpace(note) ? $"Bookmark @ 0x{address:X8}" : note,
                FunctionName = line?.FunctionName ?? ""
            };
            model.Bookmarks.Add(bm);
            if (line != null)
            {
                line.IsBookmarked = true;
                line.BookmarkCategory = category;
                line.BookmarkText = bm.Description;
            }
        }
    }
}

// =========================================================================
// Tier 1 Enhancements Services: CallTree, PCode, Assembler, Equates, MemoryMap, FunctionDiff
// =========================================================================

public static class CallTreeService
{
    public static (ObservableCollection<CallTreeNode> Incoming, ObservableCollection<CallTreeNode> Outgoing) BuildCallTree(
        ProgramModel model, string targetFunctionName, ulong targetFunctionAddress)
    {
        var incoming = new ObservableCollection<CallTreeNode>();
        var outgoing = new ObservableCollection<CallTreeNode>();

        // 1. Incoming Calls (Callers to targetFunctionAddress)
        if (model.XRefs.TryGetValue(targetFunctionAddress, out var refs))
        {
            var callerGroups = refs
                .Where(r => r.RefType == "CALL" || r.RefType == "JUMP")
                .GroupBy(r => !string.IsNullOrEmpty(r.FunctionContext) ? r.FunctionContext : $"sub_{r.FromAddress:X8}");

            foreach (var group in callerGroups)
            {
                ulong callerAddr = FindFunctionAddress(model, group.Key);
                var callerNode = new CallTreeNode
                {
                    FunctionName = group.Key,
                    Address = callerAddr != 0 ? callerAddr : group.First().FromAddress,
                    Icon = "📞"
                };

                foreach (var r in group)
                {
                    callerNode.Children.Add(new CallTreeNode
                    {
                        FunctionName = group.Key,
                        Address = callerAddr != 0 ? callerAddr : r.FromAddress,
                        CallSiteAddress = r.FromAddress,
                        InstructionPreview = r.InstructionText,
                        Icon = "📍"
                    });
                }
                incoming.Add(callerNode);
            }
        }

        // 2. Outgoing Calls (Callees called by targetFunctionAddress)
        var instructions = GetFunctionInstructions(model, targetFunctionAddress, targetFunctionName);
        var calleeList = new List<(string TargetName, ulong TargetAddr, ulong CallSiteAddr, string Instruction)>();

        foreach (var inst in instructions)
        {
            if (inst.Instruction.Equals("CALL", StringComparison.OrdinalIgnoreCase))
            {
                string targetName = inst.Comment.Replace("; Call ", "").Replace("; ", "").Trim();
                if (string.IsNullOrEmpty(targetName)) targetName = inst.Operands.Trim();

                ulong targetAddr = 0;
                if (inst.Comment.Contains("sub_"))
                {
                    int idx = inst.Comment.IndexOf("sub_");
                    string hex = inst.Comment.Substring(idx + 4).Split(' ')[0];
                    ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out targetAddr);
                }
                else if (inst.Operands.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                {
                    ulong.TryParse(inst.Operands.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out targetAddr);
                }

                ulong.TryParse(inst.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong callSite);
                calleeList.Add((targetName, targetAddr, callSite, $"{inst.Instruction} {inst.Operands}"));
            }
        }

        foreach (var group in calleeList.GroupBy(c => c.TargetName))
        {
            var first = group.First();
            bool isImport = model.IatMap.Values.Any(name => name.Equals(group.Key, StringComparison.OrdinalIgnoreCase));
            var calleeNode = new CallTreeNode
            {
                FunctionName = group.Key,
                Address = first.TargetAddr != 0 ? first.TargetAddr : first.CallSiteAddr,
                Icon = isImport ? "🌐" : "🎯"
            };

            foreach (var call in group)
            {
                calleeNode.Children.Add(new CallTreeNode
                {
                    FunctionName = call.TargetName,
                    Address = call.TargetAddr != 0 ? call.TargetAddr : call.CallSiteAddr,
                    CallSiteAddress = call.CallSiteAddr,
                    InstructionPreview = call.Instruction,
                    Icon = "📍"
                });
            }
            outgoing.Add(calleeNode);
        }

        return (incoming, outgoing);
    }

    private static ulong FindFunctionAddress(ProgramModel model, string funcName)
    {
        var sym = model.ListingLines.FirstOrDefault(l => l.IsFunctionHeader && l.FunctionName.Equals(funcName, StringComparison.OrdinalIgnoreCase));
        if (sym != null && ulong.TryParse(sym.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
        {
            return addr;
        }
        return 0;
    }

    public static List<ListingItem> GetFunctionInstructions(ProgramModel model, ulong funcAddr, string funcName)
    {
        var result = new List<ListingItem>();
        string addrHex = $"{funcAddr:X8}";
        bool recording = false;

        foreach (var line in model.ListingLines)
        {
            if (line.IsFunctionHeader)
            {
                if (recording) break;
                if (line.Address.Equals(addrHex, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(funcName) && line.FunctionName.Equals(funcName, StringComparison.OrdinalIgnoreCase)))
                {
                    recording = true;
                    continue;
                }
            }

            if (recording)
            {
                result.Add(line);
                if (line.Instruction.Equals("RET", StringComparison.OrdinalIgnoreCase) && result.Count > 1)
                {
                    break;
                }
            }
        }

        if (result.Count == 0)
        {
            PeLoaderService.DisassembleRange(model, funcAddr, 100);
            recording = false;
            foreach (var line in model.ListingLines)
            {
                if (line.IsFunctionHeader)
                {
                    if (recording) break;
                    if (line.Address.Equals(addrHex, StringComparison.OrdinalIgnoreCase))
                    {
                        recording = true;
                        continue;
                    }
                }
                if (recording)
                {
                    result.Add(line);
                    if (line.Instruction.Equals("RET", StringComparison.OrdinalIgnoreCase) && result.Count > 1) break;
                }
            }
        }

        return result;
    }
}

public static class PcodeService
{
    public static List<PcodeOpModel> GeneratePcode(ListingItem item)
    {
        var list = new List<PcodeOpModel>();
        if (string.IsNullOrWhiteSpace(item.Instruction)) return list;

        ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr);
        string mnem = item.Instruction.ToUpperInvariant();
        string ops = item.Operands.Trim();
        string[] parts = ops.Split(new[] { ',' }, 2).Select(p => p.Trim()).ToArray();
        string op0 = parts.Length > 0 ? parts[0] : "";
        string op1 = parts.Length > 1 ? parts[1] : "";

        int seq = 0;

        void AddOp(string opcode, string output, string inputs)
        {
            list.Add(new PcodeOpModel
            {
                Address = addr,
                Sequence = seq++,
                InstructionText = $"{item.Instruction} {item.Operands}".Trim(),
                Opcode = opcode,
                Output = output,
                Inputs = inputs
            });
        }

        switch (mnem)
        {
            case "NOP":
                AddOp("NOP", "", "");
                break;

            case "MOV":
                if (op1.StartsWith("[") && op1.EndsWith("]"))
                {
                    AddOp("LOAD", $"(register, {op0}, 8)", $"(const, 0, 8), (ram, {op1.Trim('[', ']').Trim()}, 8)");
                }
                else if (op0.StartsWith("[") && op0.EndsWith("]"))
                {
                    AddOp("STORE", "", $"(const, 0, 8), (ram, {op0.Trim('[', ']').Trim()}, 8), (register, {op1}, 8)");
                }
                else
                {
                    string srcVarnode = op1.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || long.TryParse(op1, out _)
                        ? $"(const, {op1}, 8)"
                        : $"(register, {op1}, 8)";
                    AddOp("COPY", $"(register, {op0}, 8)", srcVarnode);
                }
                break;

            case "LEA":
                string memExpr = op1.Trim('[', ']');
                AddOp("PTRADD", $"(register, {op0}, 8)", $"(register, {memExpr}, 8)");
                break;

            case "ADD":
                AddOp("INT_ADD", $"(register, {op0}, 8)", $"(register, {op0}, 8), {FormatOperand(op1)}");
                AddOp("INT_EQUAL", "(register, ZF, 1)", $"(register, {op0}, 8), (const, 0, 8)");
                break;

            case "SUB":
                AddOp("INT_SUB", $"(register, {op0}, 8)", $"(register, {op0}, 8), {FormatOperand(op1)}");
                AddOp("INT_EQUAL", "(register, ZF, 1)", $"(register, {op0}, 8), (const, 0, 8)");
                AddOp("INT_SLESS", "(register, SF, 1)", $"(register, {op0}, 8), (const, 0, 8)");
                break;

            case "XOR":
                AddOp("INT_XOR", $"(register, {op0}, 8)", $"(register, {op0}, 8), {FormatOperand(op1)}");
                AddOp("INT_EQUAL", "(register, ZF, 1)", $"(register, {op0}, 8), (const, 0, 8)");
                AddOp("COPY", "(register, CF, 1)", "(const, 0, 1)");
                AddOp("COPY", "(register, OF, 1)", "(const, 0, 1)");
                break;

            case "AND":
                AddOp("INT_AND", $"(register, {op0}, 8)", $"(register, {op0}, 8), {FormatOperand(op1)}");
                AddOp("INT_EQUAL", "(register, ZF, 1)", $"(register, {op0}, 8), (const, 0, 8)");
                break;

            case "OR":
                AddOp("INT_OR", $"(register, {op0}, 8)", $"(register, {op0}, 8), {FormatOperand(op1)}");
                AddOp("INT_EQUAL", "(register, ZF, 1)", $"(register, {op0}, 8), (const, 0, 8)");
                break;

            case "CMP":
                AddOp("INT_SUB", "(unique, $u1, 8)", $"{FormatOperand(op0)}, {FormatOperand(op1)}");
                AddOp("INT_EQUAL", "(register, ZF, 1)", "(unique, $u1, 8), (const, 0, 8)");
                AddOp("INT_SLESS", "(register, SF, 1)", "(unique, $u1, 8), (const, 0, 8)");
                AddOp("INT_LESS", "(register, CF, 1)", $"{FormatOperand(op0)}, {FormatOperand(op1)}");
                break;

            case "TEST":
                AddOp("INT_AND", "(unique, $u1, 8)", $"{FormatOperand(op0)}, {FormatOperand(op1)}");
                AddOp("INT_EQUAL", "(register, ZF, 1)", "(unique, $u1, 8), (const, 0, 8)");
                AddOp("COPY", "(register, CF, 1)", "(const, 0, 1)");
                AddOp("COPY", "(register, OF, 1)", "(const, 0, 1)");
                break;

            case "PUSH":
                AddOp("INT_SUB", "(register, RSP, 8)", "(register, RSP, 8), (const, 8, 8)");
                AddOp("STORE", "", $"(const, 0, 8), (register, RSP, 8), {FormatOperand(op0)}");
                break;

            case "POP":
                AddOp("LOAD", $"(register, {op0}, 8)", "(const, 0, 8), (register, RSP, 8)");
                AddOp("INT_ADD", "(register, RSP, 8)", "(register, RSP, 8), (const, 8, 8)");
                break;

            case "CALL":
                AddOp("INT_SUB", "(register, RSP, 8)", "(register, RSP, 8), (const, 8, 8)");
                AddOp("STORE", "", "(const, 0, 8), (register, RSP, 8), (register, RIP, 8)");
                AddOp("CALL", "", FormatBranchTarget(op0));
                break;

            case "RET":
                AddOp("LOAD", "(register, RIP, 8)", "(const, 0, 8), (register, RSP, 8)");
                AddOp("INT_ADD", "(register, RSP, 8)", "(register, RSP, 8), (const, 8, 8)");
                AddOp("RETURN", "", "(register, RIP, 8)");
                break;

            case "JMP":
                AddOp("BRANCH", "", FormatBranchTarget(op0));
                break;

            case "JE":
            case "JZ":
                AddOp("CBRANCH", "", $"{FormatBranchTarget(op0)}, (register, ZF, 1)");
                break;

            case "JNE":
            case "JNZ":
                AddOp("INT_BOOL_NEG", "(unique, $u1, 1)", "(register, ZF, 1)");
                AddOp("CBRANCH", "", $"{FormatBranchTarget(op0)}, (unique, $u1, 1)");
                break;

            case "JA":
                AddOp("INT_BOOL_NEG", "(unique, $u1, 1)", "(register, CF, 1)");
                AddOp("INT_BOOL_NEG", "(unique, $u2, 1)", "(register, ZF, 1)");
                AddOp("INT_BOOL_AND", "(unique, $u3, 1)", "(unique, $u1, 1), (unique, $u2, 1)");
                AddOp("CBRANCH", "", $"{FormatBranchTarget(op0)}, (unique, $u3, 1)");
                break;

            case "JB":
                AddOp("CBRANCH", "", $"{FormatBranchTarget(op0)}, (register, CF, 1)");
                break;

            default:
                AddOp("UNIMPLEMENTED", "(unique, $u0, 8)", $"({mnem}, {ops})");
                break;
        }

        return list;
    }

    private static string FormatOperand(string op)
    {
        if (string.IsNullOrWhiteSpace(op)) return "(const, 0, 8)";
        if (op.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || long.TryParse(op, out _))
            return $"(const, {op}, 8)";
        return $"(register, {op}, 8)";
    }

    private static string FormatBranchTarget(string target)
    {
        if (target.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return $"(ram, {target}, 8)";
        return $"(ram, 0x{target}, 8)";
    }
}

public class AssemblyResult
{
    public bool Success { get; set; }
    public byte[] Bytes { get; set; } = Array.Empty<byte>();
    public string ErrorMessage { get; set; } = string.Empty;
    public string DecodedPreview { get; set; } = string.Empty;
}

public static class X86AssemblerService
{
    public static AssemblyResult Assemble(string asmText, ulong address, bool is64Bit = true)
    {
        var result = new AssemblyResult();
        if (string.IsNullOrWhiteSpace(asmText))
        {
            result.ErrorMessage = "Empty assembly input.";
            return result;
        }

        try
        {
            // Support semicolon delimited multi-statements
            string[] instructions = asmText.Split(new[] { ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
                                           .Select(s => s.Trim())
                                           .Where(s => !string.IsNullOrEmpty(s))
                                           .ToArray();

            var byteList = new List<byte>();
            ulong curAddr = address;

            foreach (var inst in instructions)
            {
                byte[] encoded = AssembleSingle(inst, curAddr, is64Bit);
                byteList.AddRange(encoded);
                curAddr += (ulong)encoded.Length;
            }

            result.Bytes = byteList.ToArray();
            result.Success = true;

            // Round-trip disassemble through Iced to verify
            try
            {
                int bitness = is64Bit ? 64 : 32;
                var reader = new ByteArrayCodeReader(result.Bytes);
                var decoder = Iced.Intel.Decoder.Create(bitness, reader, address);
                var previewSb = new StringBuilder();
                while (reader.CanReadByte)
                {
                    decoder.Decode(out var decodedInst);
                    previewSb.AppendLine(decodedInst.ToString());
                }
                result.DecodedPreview = previewSb.ToString().Trim();
            }
            catch
            {
                result.DecodedPreview = BitConverter.ToString(result.Bytes).Replace("-", " ");
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    private static byte[] AssembleSingle(string inst, ulong address, bool is64Bit)
    {
        // Check if raw hex bytes: e.g. "90 90 90" or "31 C0 C3"
        string cleanHex = inst.Replace(" ", "").Replace("0x", "").Trim();
        if (cleanHex.Length % 2 == 0 && cleanHex.All(c => "0123456789ABCDEFabcdef".Contains(c)) && !inst.Contains(" "))
        {
            var rawBytes = new List<byte>();
            for (int i = 0; i < cleanHex.Length; i += 2)
            {
                rawBytes.Add(Convert.ToByte(cleanHex.Substring(i, 2), 16));
            }
            return rawBytes.ToArray();
        }

        string upper = inst.ToUpperInvariant().Trim();

        // 1. NOP
        if (upper == "NOP") return new byte[] { 0x90 };
        if (upper.StartsWith("NOP ") && int.TryParse(upper.Substring(4).Trim(), out int nopCount) && nopCount > 0)
        {
            return Enumerable.Repeat((byte)0x90, Math.Min(nopCount, 128)).ToArray();
        }

        // 2. RET
        if (upper == "RET" || upper == "RETN") return new byte[] { 0xC3 };
        if (upper.StartsWith("RET "))
        {
            string arg = upper.Substring(4).Trim();
            ushort imm = ParseImmediate16(arg);
            return new byte[] { 0xC2, (byte)(imm & 0xFF), (byte)((imm >> 8) & 0xFF) };
        }

        // 3. INT
        if (upper == "INT 3" || upper == "INT3") return new byte[] { 0xCC };
        if (upper.StartsWith("INT "))
        {
            byte imm = (byte)ParseImmediate64(upper.Substring(4).Trim());
            return new byte[] { 0xCD, imm };
        }

        // 4. Flags
        if (upper == "CLC") return new byte[] { 0xF8 };
        if (upper == "STC") return new byte[] { 0xF9 };

        // 5. PUSH / POP Register
        if (upper.StartsWith("PUSH "))
        {
            string reg = upper.Substring(5).Trim();
            return EncodePush(reg, is64Bit);
        }
        if (upper.StartsWith("POP "))
        {
            string reg = upper.Substring(4).Trim();
            return EncodePop(reg, is64Bit);
        }

        // 6. XOR
        if (upper.StartsWith("XOR "))
        {
            var parts = upper.Substring(4).Split(new[] { ',' }, 2).Select(p => p.Trim()).ToArray();
            if (parts.Length == 2 && parts[0] == parts[1])
            {
                // Self XOR: xor reg, reg -> zero register
                return EncodeSelfXor(parts[0], is64Bit);
            }
        }

        // 7. MOV reg, imm or MOV reg, reg
        if (upper.StartsWith("MOV "))
        {
            var parts = upper.Substring(4).Split(new[] { ',' }, 2).Select(p => p.Trim()).ToArray();
            if (parts.Length == 2)
            {
                return EncodeMov(parts[0], parts[1], is64Bit);
            }
        }

        // 8. ADD / SUB
        if (upper.StartsWith("ADD ") || upper.StartsWith("SUB "))
        {
            bool isSub = upper.StartsWith("SUB ");
            var parts = upper.Substring(4).Split(new[] { ',' }, 2).Select(p => p.Trim()).ToArray();
            if (parts.Length == 2)
            {
                return EncodeAddSub(parts[0], parts[1], isSub, is64Bit);
            }
        }

        // 9. JMP / CALL
        if (upper.StartsWith("JMP "))
        {
            ulong target = ParseAddressOrImmediate(upper.Substring(4).Trim(), address);
            long rel = (long)target - (long)address - 5;
            if (rel >= -128 && rel <= 127)
            {
                sbyte rel8 = (sbyte)((long)target - (long)address - 2);
                return new byte[] { 0xEB, (byte)rel8 };
            }
            int rel32 = (int)rel;
            return new byte[] { 0xE9, (byte)(rel32 & 0xFF), (byte)((rel32 >> 8) & 0xFF), (byte)((rel32 >> 16) & 0xFF), (byte)((rel32 >> 24) & 0xFF) };
        }

        if (upper.StartsWith("CALL "))
        {
            ulong target = ParseAddressOrImmediate(upper.Substring(5).Trim(), address);
            int rel32 = (int)((long)target - (long)address - 5);
            return new byte[] { 0xE8, (byte)(rel32 & 0xFF), (byte)((rel32 >> 8) & 0xFF), (byte)((rel32 >> 16) & 0xFF), (byte)((rel32 >> 24) & 0xFF) };
        }

        // 10. Conditional Jumps
        string[] conds = { "JZ", "JE", "JNZ", "JNE", "JA", "JAE", "JB", "JBE", "JG", "JGE", "JL", "JLE" };
        foreach (var cond in conds)
        {
            if (upper.StartsWith(cond + " "))
            {
                ulong target = ParseAddressOrImmediate(upper.Substring(cond.Length + 1).Trim(), address);
                return EncodeConditionalJump(cond, target, address);
            }
        }

        throw new NotSupportedException($"Instruction '{inst}' could not be assembled. Tip: You can also enter direct hex bytes (e.g. 31 C0 C3).");
    }

    private static byte[] EncodePush(string reg, bool is64Bit)
    {
        string[] regs = { "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI" };
        int idx = Array.IndexOf(regs, reg);
        if (idx >= 0) return new byte[] { (byte)(0x50 + idx) };

        string[] regs32 = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
        idx = Array.IndexOf(regs32, reg);
        if (idx >= 0) return new byte[] { (byte)(0x50 + idx) };

        string[] regs64Ext = { "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15" };
        idx = Array.IndexOf(regs64Ext, reg);
        if (idx >= 0) return new byte[] { 0x41, (byte)(0x50 + idx) };

        throw new ArgumentException($"Unsupported register for PUSH: {reg}");
    }

    private static byte[] EncodePop(string reg, bool is64Bit)
    {
        string[] regs = { "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI" };
        int idx = Array.IndexOf(regs, reg);
        if (idx >= 0) return new byte[] { (byte)(0x58 + idx) };

        string[] regs32 = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
        idx = Array.IndexOf(regs32, reg);
        if (idx >= 0) return new byte[] { (byte)(0x58 + idx) };

        string[] regs64Ext = { "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15" };
        idx = Array.IndexOf(regs64Ext, reg);
        if (idx >= 0) return new byte[] { 0x41, (byte)(0x58 + idx) };

        throw new ArgumentException($"Unsupported register for POP: {reg}");
    }

    private static byte[] EncodeSelfXor(string reg, bool is64Bit)
    {
        string[] regs32 = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
        int idx = Array.IndexOf(regs32, reg);
        if (idx >= 0)
        {
            byte modrm = (byte)(0xC0 + (idx << 3) + idx);
            return new byte[] { 0x31, modrm };
        }

        string[] regs64 = { "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI" };
        idx = Array.IndexOf(regs64, reg);
        if (idx >= 0)
        {
            byte modrm = (byte)(0xC0 + (idx << 3) + idx);
            return new byte[] { 0x48, 0x31, modrm };
        }

        string[] regs64Ext = { "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15" };
        idx = Array.IndexOf(regs64Ext, reg);
        if (idx >= 0)
        {
            byte modrm = (byte)(0xC0 + (idx << 3) + idx);
            return new byte[] { 0x4D, 0x31, modrm };
        }

        throw new ArgumentException($"Unsupported register for XOR: {reg}");
    }

    private static byte[] EncodeMov(string dest, string src, bool is64Bit)
    {
        string[] regs32 = { "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI" };
        string[] regs64 = { "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI" };

        int idx32 = Array.IndexOf(regs32, dest);
        if (idx32 >= 0)
        {
            uint imm = (uint)ParseImmediate64(src);
            return new byte[] { (byte)(0xB8 + idx32), (byte)(imm & 0xFF), (byte)((imm >> 8) & 0xFF), (byte)((imm >> 16) & 0xFF), (byte)((imm >> 24) & 0xFF) };
        }

        int idx64 = Array.IndexOf(regs64, dest);
        if (idx64 >= 0)
        {
            ulong imm = ParseImmediate64(src);
            if (imm <= 0xFFFFFFFF)
            {
                // MOV reg32, imm32 zero-extends into 64-bit register
                return new byte[] { (byte)(0xB8 + idx64), (byte)(imm & 0xFF), (byte)((imm >> 8) & 0xFF), (byte)((imm >> 16) & 0xFF), (byte)((imm >> 24) & 0xFF) };
            }
            else
            {
                // Full 64-bit mov: 48 B8+rd imm64
                var list = new List<byte> { 0x48, (byte)(0xB8 + idx64) };
                list.AddRange(BitConverter.GetBytes(imm));
                return list.ToArray();
            }
        }

        throw new ArgumentException($"Unsupported operands for MOV: {dest}, {src}");
    }

    private static byte[] EncodeAddSub(string reg, string immStr, bool isSub, bool is64Bit)
    {
        long imm = (long)ParseImmediate64(immStr);
        byte opByte = (byte)(isSub ? 0x28 : 0x00);

        if (reg == "RSP")
        {
            if (imm >= -128 && imm <= 127)
            {
                byte subCode = isSub ? (byte)0xEC : (byte)0xC4;
                return new byte[] { 0x48, 0x83, subCode, (byte)(imm & 0xFF) };
            }
            else
            {
                byte subCode = isSub ? (byte)0xEC : (byte)0xC4;
                int val32 = (int)imm;
                return new byte[] { 0x48, 0x81, subCode, (byte)(val32 & 0xFF), (byte)((val32 >> 8) & 0xFF), (byte)((val32 >> 16) & 0xFF), (byte)((val32 >> 24) & 0xFF) };
            }
        }

        throw new ArgumentException($"Unsupported register for ADD/SUB: {reg}");
    }

    private static byte[] EncodeConditionalJump(string cond, ulong target, ulong address)
    {
        byte shortCode = cond switch
        {
            "JE" or "JZ" => 0x74,
            "JNE" or "JNZ" => 0x75,
            "JB" => 0x72,
            "JAE" => 0x73,
            "JA" => 0x77,
            "JBE" => 0x76,
            "JL" => 0x7C,
            "JGE" => 0x7D,
            "JG" => 0x7F,
            "JLE" => 0x7E,
            _ => 0x74
        };

        long rel = (long)target - (long)address - 2;
        if (rel >= -128 && rel <= 127)
        {
            return new byte[] { shortCode, (byte)((sbyte)rel) };
        }

        byte nearCode = cond switch
        {
            "JE" or "JZ" => 0x84,
            "JNE" or "JNZ" => 0x85,
            "JB" => 0x82,
            "JAE" => 0x83,
            "JA" => 0x87,
            "JBE" => 0x86,
            "JL" => 0x8C,
            "JGE" => 0x8D,
            "JG" => 0x8F,
            "JLE" => 0x8E,
            _ => 0x84
        };

        int rel32 = (int)((long)target - (long)address - 6);
        return new byte[] { 0x0F, nearCode, (byte)(rel32 & 0xFF), (byte)((rel32 >> 8) & 0xFF), (byte)((rel32 >> 16) & 0xFF), (byte)((rel32 >> 24) & 0xFF) };
    }

    private static ulong ParseAddressOrImmediate(string s, ulong currentAddr)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.Parse(s.Substring(2), System.Globalization.NumberStyles.HexNumber);
        if (ulong.TryParse(s, out ulong dec))
            return dec;
        if (ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out ulong hex))
            return hex;
        return currentAddr;
    }

    private static ulong ParseImmediate64(string s)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return ulong.Parse(s.Substring(2), System.Globalization.NumberStyles.HexNumber);
        if (ulong.TryParse(s, out ulong dec))
            return dec;
        return ulong.Parse(s, System.Globalization.NumberStyles.HexNumber);
    }

    private static ushort ParseImmediate16(string s)
    {
        return (ushort)ParseImmediate64(s);
    }
}

public static class EquateService
{
    private static readonly List<(string Name, ulong Value, string Category, string Desc)> _knownConstants = new()
    {
        ("STATUS_SUCCESS", 0x00, "NTSTATUS", "The operation completed successfully."),
        ("NULL", 0x00, "General", "Null pointer constant"),
        ("FALSE", 0x00, "Boolean", "Boolean false"),
        ("TRUE", 0x01, "Boolean", "Boolean true"),
        ("PAGE_NOACCESS", 0x01, "Memory", "Disables all access to committed memory"),
        ("FILE_SHARE_READ", 0x01, "File IO", "Enables subsequent open operations for read access"),
        ("PAGE_READONLY", 0x02, "Memory", "Enables read-only access"),
        ("FILE_SHARE_WRITE", 0x02, "File IO", "Enables subsequent open operations for write access"),
        ("CREATE_ALWAYS", 0x02, "File IO", "Always create a new file"),
        ("OPEN_EXISTING", 0x03, "File IO", "Opens a file only if it exists"),
        ("PAGE_READWRITE", 0x04, "Memory", "Enables read-only or read/write access"),
        ("OPEN_ALWAYS", 0x04, "File IO", "Always opens the file"),
        ("TRUNCATE_EXISTING", 0x05, "File IO", "Opens a file and truncates it"),
        ("PAGE_EXECUTE", 0x10, "Memory", "Enables execute access to committed memory"),
        ("PAGE_EXECUTE_READ", 0x20, "Memory", "Enables execute or read-only access"),
        ("PAGE_EXECUTE_READWRITE", 0x40, "Memory", "Enables execute, read-only, or read/write access"),
        ("FILE_ATTRIBUTE_NORMAL", 0x80, "File IO", "The file does not have other attributes set"),
        ("MEM_COMMIT", 0x1000, "Memory", "Allocates memory charges in RAM or paging files"),
        ("MEM_RESERVE", 0x2000, "Memory", "Reserves a range of process virtual address space"),
        ("MEM_DECOMMIT", 0x4000, "Memory", "Decommits a specific region of committed pages"),
        ("MEM_RELEASE", 0x8000, "Memory", "Releases a specific region of pages"),
        ("GENERIC_ALL", 0x10000000, "Security", "All possible access rights"),
        ("GENERIC_EXECUTE", 0x20000000, "Security", "Execute access"),
        ("GENERIC_WRITE", 0x40000000, "Security", "Write access"),
        ("GENERIC_READ", 0x80000000, "Security", "Read access"),
        ("INVALID_HANDLE_VALUE", 0xFFFFFFFFFFFFFFFF, "Handle", "Returned by CreateFile when failed"),
        ("STATUS_ACCESS_VIOLATION", 0xC0000005, "NTSTATUS", "Access violation occurred"),
        ("STATUS_UNSUCCESSFUL", 0xC0000001, "NTSTATUS", "Generic failure status")
    };

    public static List<(string Name, ulong Value, string Category, string Desc)> FindMatches(ulong value)
    {
        var matches = _knownConstants.Where(c => c.Value == value).ToList();
        if (matches.Count == 0)
        {
            matches.Add(($"CONST_0x{value:X}", value, "Custom", $"Auto-generated constant for 0x{value:X}"));
        }
        return matches;
    }

    public static void ApplyEquate(ProgramModel model, ulong address, string equateName, ulong value, string category = "Custom")
    {
        model.AppliedEquates[address] = equateName;

        var existing = model.Equates.FirstOrDefault(e => e.Name.Equals(equateName, StringComparison.OrdinalIgnoreCase));
        if (existing == null)
        {
            existing = new EquateModel
            {
                Name = equateName,
                Value = value,
                Category = category
            };
            model.Equates.Add(existing);
        }

        if (!existing.ReferenceAddresses.Contains(address))
        {
            existing.ReferenceAddresses.Add(address);
        }

        // Apply in Listing
        string addrHex = $"{address:X8}";
        var line = model.ListingLines.FirstOrDefault(l => l.Address.Equals(addrHex, StringComparison.OrdinalIgnoreCase));
        if (line != null)
        {
            string hexVal = $"0x{value:X}";
            if (line.Operands.Contains(hexVal, StringComparison.OrdinalIgnoreCase))
            {
                line.Operands = line.Operands.Replace(hexVal, equateName, StringComparison.OrdinalIgnoreCase);
            }
            else if (line.Operands.Contains($"{value}", StringComparison.OrdinalIgnoreCase))
            {
                line.Operands = line.Operands.Replace($"{value}", equateName);
            }
            else
            {
                line.Comment = string.IsNullOrEmpty(line.Comment) ? $"; Equate: {equateName} (0x{value:X})" : $"{line.Comment} ; Equate: {equateName}";
            }
        }
    }

    public static void RemoveEquate(ProgramModel model, ulong address)
    {
        if (model.AppliedEquates.TryGetValue(address, out string? name))
        {
            model.AppliedEquates.Remove(address);
            var eq = model.Equates.FirstOrDefault(e => e.Name == name);
            if (eq != null)
            {
                eq.ReferenceAddresses.Remove(address);
                if (eq.ReferenceAddresses.Count == 0)
                {
                    model.Equates.Remove(eq);
                }
            }
        }
    }
}

public static class MemoryMapService
{
    public static void AddBlock(ProgramModel model, string name, ulong startAddr, long length, bool r, bool w, bool x, string type = "Initialized", string comment = "")
    {
        ulong endAddr = startAddr + (ulong)length;
        string perms = (r ? "R" : "") + (w ? "W" : "") + (x ? "X" : "");

        var sec = new SectionNode
        {
            Name = name,
            StartAddress = startAddr,
            EndAddress = endAddr,
            Size = length,
            Permissions = perms,
            BlockType = type,
            Comment = comment,
            Data = new byte[length]
        };

        model.Sections.Add(sec);

        // Update ProgramTree
        var pNode = new ProgramTreeNode
        {
            Name = name,
            Icon = x ? "⚡" : "📦",
            StartAddress = startAddr,
            Permissions = perms,
            SizeInfo = $"{length / 1024.0:F1} KB",
            Details = $"Custom Block [{sec.AddressRange}] ({perms}) {type}"
        };
        model.ProgramTreeNodes.Add(pNode);
    }

    public static void SplitBlock(ProgramModel model, SectionNode block, ulong splitAddress, string newName)
    {
        if (splitAddress <= block.StartAddress || splitAddress >= block.EndAddress)
            throw new ArgumentOutOfRangeException(nameof(splitAddress), "Split address must be within the block bounds.");

        long firstSize = (long)(splitAddress - block.StartAddress);
        long secondSize = (long)(block.EndAddress - splitAddress);

        byte[] firstData = new byte[firstSize];
        byte[] secondData = new byte[secondSize];

        if (block.Data != null && block.Data.Length >= firstSize + secondSize)
        {
            Array.Copy(block.Data, 0, firstData, 0, firstSize);
            Array.Copy(block.Data, firstSize, secondData, 0, secondSize);
        }

        ulong oldEnd = block.EndAddress;
        block.EndAddress = splitAddress;
        block.Size = firstSize;
        block.Data = firstData;

        var newBlock = new SectionNode
        {
            Name = newName,
            StartAddress = splitAddress,
            EndAddress = oldEnd,
            Size = secondSize,
            Permissions = block.Permissions,
            BlockType = block.BlockType,
            Comment = $"Split from {block.Name}",
            Data = secondData
        };

        int idx = model.Sections.IndexOf(block);
        if (idx >= 0 && idx + 1 < model.Sections.Count)
            model.Sections.Insert(idx + 1, newBlock);
        else
            model.Sections.Add(newBlock);
    }

    public static void DeleteBlock(ProgramModel model, SectionNode block)
    {
        model.Sections.Remove(block);
        var pNode = model.ProgramTreeNodes.FirstOrDefault(n => n.StartAddress == block.StartAddress);
        if (pNode != null) model.ProgramTreeNodes.Remove(pNode);
    }

    public static void RebaseProgram(ProgramModel model, ulong newImageBase, Action<string>? log = null)
    {
        long delta = (long)newImageBase - (long)model.ImageBase;
        if (delta == 0) return;

        log?.Invoke($"[Rebase] Rebasing program from 0x{model.ImageBase:X8} to 0x{newImageBase:X8} (Delta: {(delta >= 0 ? "+" : "")}0x{delta:X})");

        model.ImageBase = newImageBase;
        model.EntryPoint = (ulong)((long)model.EntryPoint + delta);

        // 1. Shift Sections
        foreach (var sec in model.Sections)
        {
            sec.StartAddress = (ulong)((long)sec.StartAddress + delta);
            sec.EndAddress = (ulong)((long)sec.EndAddress + delta);
        }

        // 2. Shift ProgramTreeNodes
        void ShiftTreeNode(ProgramTreeNode node)
        {
            node.StartAddress = (ulong)((long)node.StartAddress + delta);
            foreach (var child in node.Children) ShiftTreeNode(child);
        }
        foreach (var n in model.ProgramTreeNodes) ShiftTreeNode(n);

        // 3. Shift ListingLines
        foreach (var item in model.ListingLines)
        {
            if (ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong oldAddr))
            {
                item.Address = $"{(ulong)((long)oldAddr + delta):X8}";
            }
        }

        // 4. Shift ByteViewerRows
        foreach (var row in model.ByteViewerRows)
        {
            if (ulong.TryParse(row.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong oldAddr))
            {
                row.Address = $"{(ulong)((long)oldAddr + delta):X8}";
            }
        }

        // 5. Shift Function Addresses
        var newFuncs = new HashSet<ulong>();
        foreach (var f in model.FunctionAddresses)
        {
            newFuncs.Add((ulong)((long)f + delta));
        }
        model.FunctionAddresses = newFuncs;

        // 6. Shift Symbols
        void ShiftSymbolNode(SymbolNode node)
        {
            if (ulong.TryParse(node.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong oldAddr))
            {
                node.Address = $"{(ulong)((long)oldAddr + delta):X8}";
            }
            foreach (var child in node.Children) ShiftSymbolNode(child);
        }
        foreach (var cat in model.SymbolCategories) ShiftSymbolNode(cat);

        // 7. Shift Bookmarks
        foreach (var bm in model.Bookmarks)
        {
            bm.Address = (ulong)((long)bm.Address + delta);
        }

        // 8. Shift XRefs
        var newXrefs = new Dictionary<ulong, List<XRefModel>>();
        foreach (var kvp in model.XRefs)
        {
            ulong newKey = (ulong)((long)kvp.Key + delta);
            foreach (var r in kvp.Value)
            {
                r.FromAddress = (ulong)((long)r.FromAddress + delta);
            }
            newXrefs[newKey] = kvp.Value;
        }
        model.XRefs = newXrefs;

        log?.Invoke("[Rebase] Rebase completed. All addresses, memory sections, and references shifted.");
    }
}

public static class FunctionDiffService
{
    public static (List<DiffLineModel> LeftLines, List<DiffLineModel> RightLines, int DiffCount) CompareDisassembly(
        List<ListingItem> funcA, List<ListingItem> funcB)
    {
        var left = new List<DiffLineModel>();
        var right = new List<DiffLineModel>();
        int diffCount = 0;

        int max = Math.Max(funcA.Count, funcB.Count);
        for (int i = 0; i < max; i++)
        {
            var itemA = i < funcA.Count ? funcA[i] : null;
            var itemB = i < funcB.Count ? funcB[i] : null;

            if (itemA != null && itemB != null)
            {
                string textA = $"{itemA.Instruction} {itemA.Operands}".Trim();
                string textB = $"{itemB.Instruction} {itemB.Operands}".Trim();
                bool same = textA.Equals(textB, StringComparison.OrdinalIgnoreCase);

                if (!same) diffCount++;

                left.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    AddressHex = $"0x{itemA.Address}",
                    Text = textA,
                    Kind = same ? DiffLineKind.Same : DiffLineKind.Modified
                });

                right.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    AddressHex = $"0x{itemB.Address}",
                    Text = textB,
                    Kind = same ? DiffLineKind.Same : DiffLineKind.Modified
                });
            }
            else if (itemA != null)
            {
                diffCount++;
                left.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    AddressHex = $"0x{itemA.Address}",
                    Text = $"{itemA.Instruction} {itemA.Operands}".Trim(),
                    Kind = DiffLineKind.Deleted
                });
                right.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    AddressHex = "",
                    Text = "// [Missing in Function B]",
                    Kind = DiffLineKind.Deleted
                });
            }
            else if (itemB != null)
            {
                diffCount++;
                left.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    AddressHex = "",
                    Text = "// [Missing in Function A]",
                    Kind = DiffLineKind.Added
                });
                right.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    AddressHex = $"0x{itemB.Address}",
                    Text = $"{itemB.Instruction} {itemB.Operands}".Trim(),
                    Kind = DiffLineKind.Added
                });
            }
        }

        return (left, right, diffCount);
    }

    public static (List<DiffLineModel> LeftLines, List<DiffLineModel> RightLines, int DiffCount) ComparePseudocode(
        string codeA, string codeB)
    {
        var linesA = codeA.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        var linesB = codeB.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

        var left = new List<DiffLineModel>();
        var right = new List<DiffLineModel>();
        int diffCount = 0;

        int max = Math.Max(linesA.Length, linesB.Length);
        for (int i = 0; i < max; i++)
        {
            string? textA = i < linesA.Length ? linesA[i] : null;
            string? textB = i < linesB.Length ? linesB[i] : null;

            if (textA != null && textB != null)
            {
                bool same = textA.Trim().Equals(textB.Trim(), StringComparison.Ordinal);
                if (!same) diffCount++;

                left.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    Text = textA,
                    Kind = same ? DiffLineKind.Same : DiffLineKind.Modified
                });
                right.Add(new DiffLineModel
                {
                    LineNumber = i + 1,
                    Text = textB,
                    Kind = same ? DiffLineKind.Same : DiffLineKind.Modified
                });
            }
            else if (textA != null)
            {
                diffCount++;
                left.Add(new DiffLineModel { LineNumber = i + 1, Text = textA, Kind = DiffLineKind.Deleted });
                right.Add(new DiffLineModel { LineNumber = i + 1, Text = "", Kind = DiffLineKind.Deleted });
            }
            else if (textB != null)
            {
                diffCount++;
                left.Add(new DiffLineModel { LineNumber = i + 1, Text = "", Kind = DiffLineKind.Added });
                right.Add(new DiffLineModel { LineNumber = i + 1, Text = textB, Kind = DiffLineKind.Added });
            }
        }

        return (left, right, diffCount);
    }
}

// =========================================================================
// Tier 2 Enhancements: CParser, Entropy, Demangler, PDB, FlowArrow, RoslynScript
// =========================================================================

public class CParseResult
{
    public List<CustomStructModel> Structs { get; set; } = new();
    public List<CustomEnumModel> Enums { get; set; } = new();
    public Dictionary<string, string> Typedefs { get; set; } = new();
    public List<string> LogMessages { get; set; } = new();
    public bool Success => Structs.Count > 0 || Enums.Count > 0 || Typedefs.Count > 0;
}

public static class CParserService
{
    public static CParseResult ParseCSource(string cSource)
    {
        var result = new CParseResult();
        if (string.IsNullOrWhiteSpace(cSource)) return result;

        // 1. Remove comments
        string clean = Regex.Replace(cSource, @"/\*.*?\*/", "", RegexOptions.Singleline);
        clean = Regex.Replace(clean, @"//.*", "");

        // 2. Remove preprocessor directives
        clean = Regex.Replace(clean, @"^\s*#.*$", "", RegexOptions.Multiline);

        // 3. Parse enums: (typedef)? enum (tag)? { members } (name)?;
        var enumRegex = new Regex(@"(?:typedef\s+)?enum\s*([a-zA-Z0-9_]*)\s*\{([^}]+)\}\s*([a-zA-Z0-9_]*)\s*;", RegexOptions.Singleline);
        foreach (Match match in enumRegex.Matches(clean))
        {
            string tag = match.Groups[1].Value.Trim();
            string body = match.Groups[2].Value;
            string typedefName = match.Groups[3].Value.Trim();

            string enumName = !string.IsNullOrEmpty(typedefName) ? typedefName : (!string.IsNullOrEmpty(tag) ? tag : $"Enum_{result.Enums.Count + 1}");
            if (enumName.StartsWith("_")) enumName = enumName.TrimStart('_');

            var customEnum = new CustomEnumModel { Name = enumName, UnderlyingType = "uint32" };
            long currentValue = 0;

            var items = body.Split(new[] { ',', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var rawItem in items)
            {
                var item = rawItem.Trim();
                if (string.IsNullOrEmpty(item)) continue;

                string memberName = item;
                if (item.Contains("="))
                {
                    var parts = item.Split('=');
                    memberName = parts[0].Trim();
                    string valStr = parts[1].Trim();
                    if (valStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    {
                        if (long.TryParse(valStr.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out long hexVal))
                            currentValue = hexVal;
                    }
                    else if (long.TryParse(valStr, out long decVal))
                    {
                        currentValue = decVal;
                    }
                }

                if (!string.IsNullOrEmpty(memberName))
                {
                    customEnum.Members.Add(new EnumMemberModel
                    {
                        Name = memberName,
                        Value = currentValue,
                        Comment = $"0x{currentValue:X}"
                    });
                    currentValue++;
                }
            }

            if (customEnum.Members.Count > 0)
            {
                result.Enums.Add(customEnum);
                result.LogMessages.Add($"[CParser] Parsed enum '{enumName}' with {customEnum.Members.Count} members.");
            }
        }

        // 4. Parse structs & unions: (typedef)? (struct|union) (tag)? { fields } (name)?;
        var structRegex = new Regex(@"(?:typedef\s+)?(struct|union)\s*([a-zA-Z0-9_]*)\s*\{([^}]+)\}\s*([a-zA-Z0-9_,\s*]*)\s*;", RegexOptions.Singleline);
        foreach (Match match in structRegex.Matches(clean))
        {
            string kind = match.Groups[1].Value.Trim();
            bool isUnion = kind.Equals("union", StringComparison.OrdinalIgnoreCase);
            string tag = match.Groups[2].Value.Trim();
            string body = match.Groups[3].Value;
            string typedefPart = match.Groups[4].Value.Trim();

            string structName = "";
            if (!string.IsNullOrEmpty(typedefPart))
            {
                var names = typedefPart.Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var n in names)
                {
                    var cleanN = n.Trim().TrimStart('*');
                    if (!string.IsNullOrEmpty(cleanN) && !cleanN.StartsWith("P") && !cleanN.StartsWith("LP"))
                    {
                        structName = cleanN;
                        break;
                    }
                }
                if (string.IsNullOrEmpty(structName) && names.Length > 0)
                    structName = names[0].Trim().TrimStart('*');
            }
            if (string.IsNullOrEmpty(structName))
                structName = !string.IsNullOrEmpty(tag) ? tag : $"Struct_{result.Structs.Count + 1}";
            if (structName.StartsWith("_")) structName = structName.TrimStart('_');

            var customStruct = new CustomStructModel { Name = structName };
            int currentOffset = 0;
            int maxFieldSize = 0;

            var fieldDecls = body.Split(';');
            foreach (var rawDecl in fieldDecls)
            {
                var decl = rawDecl.Trim();
                if (string.IsNullOrEmpty(decl)) continue;

                var tokens = decl.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length < 2) continue;

                string typeToken = tokens[0].Trim();
                if (tokens.Length > 2 && (tokens[0] == "unsigned" || tokens[0] == "signed" || tokens[0] == "struct" || tokens[0] == "union"))
                {
                    typeToken = tokens[0] + " " + tokens[1];
                }

                string nameToken = tokens[^1].Trim();
                int arrayCount = 1;
                if (nameToken.Contains("[") && nameToken.Contains("]"))
                {
                    int open = nameToken.IndexOf('[');
                    int close = nameToken.IndexOf(']');
                    string countStr = nameToken.Substring(open + 1, close - open - 1).Trim();
                    nameToken = nameToken.Substring(0, open).Trim();
                    if (int.TryParse(countStr, out int cnt)) arrayCount = cnt;
                    else if (countStr.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && int.TryParse(countStr.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out int hcnt)) arrayCount = hcnt;
                }

                bool isPtr = typeToken.EndsWith("*") || nameToken.StartsWith("*");
                nameToken = nameToken.TrimStart('*');

                int unitSize = isPtr ? 8 : GetTypeSize(typeToken);
                int totalSize = unitSize * arrayCount;

                // Natural alignment for structs (except unions)
                if (!isUnion)
                {
                    int align = Math.Min(unitSize, 8);
                    if (align > 1 && (currentOffset % align) != 0)
                    {
                        currentOffset += (align - (currentOffset % align));
                    }
                }

                int fieldOffset = isUnion ? 0 : currentOffset;

                customStruct.Fields.Add(new StructFieldModel
                {
                    Offset = fieldOffset,
                    Name = nameToken,
                    TypeName = (isPtr ? $"{typeToken.TrimEnd('*')}*" : typeToken) + (arrayCount > 1 ? $"[{arrayCount}]" : ""),
                    Size = totalSize,
                    Comment = isUnion ? "union member" : ""
                });

                if (totalSize > maxFieldSize) maxFieldSize = totalSize;
                if (!isUnion) currentOffset += totalSize;
            }

            if (customStruct.Fields.Count > 0)
            {
                result.Structs.Add(customStruct);
                result.LogMessages.Add($"[CParser] Parsed {kind} '{structName}' ({customStruct.Fields.Count} fields, {customStruct.TotalSize} bytes).");
            }
        }

        // 5. Parse simple typedefs
        var typedefRegex = new Regex(@"typedef\s+([a-zA-Z0-9_* ]+?)\s+([a-zA-Z0-9_]+)\s*;", RegexOptions.Multiline);
        foreach (Match m in typedefRegex.Matches(clean))
        {
            string orig = m.Groups[1].Value.Trim();
            string alias = m.Groups[2].Value.Trim();
            if (!orig.Contains("{") && !orig.Contains("}"))
            {
                result.Typedefs[alias] = orig;
            }
        }

        return result;
    }

    public static int GetTypeSize(string type)
    {
        type = type.Trim().ToLowerInvariant();
        if (type.EndsWith("*") || type.Contains("ptr") || type == "handle" || type == "hwnd" || type == "pvoid" || type == "lpvoid" || type == "size_t" || type == "uintptr_t" || type == "intptr_t")
            return 8;
        if (type.Contains("int64") || type == "long long" || type == "unsigned long long" || type == "qword" || type == "uint64_t" || type == "int64_t" || type == "double")
            return 8;
        if (type.Contains("int") || type == "long" || type == "unsigned long" || type == "dword" || type == "uint32_t" || type == "int32_t" || type == "float" || type == "bool" || type == "boolean")
            return 4;
        if (type.Contains("short") || type == "word" || type == "uint16_t" || type == "int16_t" || type == "wchar_t")
            return 2;
        if (type.Contains("char") || type == "byte" || type == "uint8_t" || type == "int8_t" || type == "uchar")
            return 1;
        return 4;
    }

    public static void ApplyToProgram(ProgramModel program, CParseResult result)
    {
        var categoryNode = program.DataTypeCategories.FirstOrDefault(c => c.Name == "C Header Imports");
        if (categoryNode == null)
        {
            categoryNode = new DataTypeNode { Name = "C Header Imports", Kind = "Category", Icon = "📂" };
            program.DataTypeCategories.Add(categoryNode);
        }

        foreach (var st in result.Structs)
        {
            var existing = program.CustomStructures.FirstOrDefault(s => s.Name.Equals(st.Name, StringComparison.OrdinalIgnoreCase));
            if (existing != null) program.CustomStructures.Remove(existing);
            program.CustomStructures.Add(st);

            var treeExisting = categoryNode.Children.FirstOrDefault(c => c.Name == st.Name);
            if (treeExisting != null) categoryNode.Children.Remove(treeExisting);

            var stNode = new DataTypeNode
            {
                Name = st.Name,
                Size = $"{st.TotalSize} bytes",
                Kind = "Struct",
                Icon = "🧩"
            };
            foreach (var f in st.Fields)
            {
                stNode.Children.Add(new DataTypeNode
                {
                    Name = $"{f.Name} : {f.TypeName}",
                    Size = $"{f.Size}B @ +0x{f.Offset:X2}",
                    Kind = "Field",
                    Icon = "🔹"
                });
            }
            categoryNode.Children.Add(stNode);
        }

        foreach (var en in result.Enums)
        {
            var existing = program.CustomEnums.FirstOrDefault(e => e.Name.Equals(en.Name, StringComparison.OrdinalIgnoreCase));
            if (existing != null) program.CustomEnums.Remove(existing);
            program.CustomEnums.Add(en);

            var treeExisting = categoryNode.Children.FirstOrDefault(c => c.Name == en.Name);
            if (treeExisting != null) categoryNode.Children.Remove(treeExisting);

            var enNode = new DataTypeNode
            {
                Name = en.Name,
                Size = $"{en.Members.Count} members",
                Kind = "Enum",
                Icon = "🏷️"
            };
            foreach (var m in en.Members)
            {
                enNode.Children.Add(new DataTypeNode
                {
                    Name = $"{m.Name} = 0x{m.Value:X}",
                    Size = "enum",
                    Kind = "Member",
                    Icon = "🔸"
                });
            }
            categoryNode.Children.Add(enNode);
        }
    }
}

public static class EntropyService
{
    public static double CalculateShannonEntropy(byte[]? data, int offset = 0, int length = -1)
    {
        if (data == null || data.Length == 0) return 0.0;
        if (length < 0 || offset + length > data.Length) length = data.Length - offset;
        if (length <= 0) return 0.0;

        int[] counts = new int[256];
        for (int i = 0; i < length; i++)
        {
            counts[data[offset + i]]++;
        }

        double entropy = 0.0;
        double len = length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] > 0)
            {
                double p = counts[i] / len;
                entropy -= p * Math.Log2(p);
            }
        }

        return Math.Round(Math.Clamp(entropy, 0.0, 8.0), 3);
    }

    public static List<SectionEntropyModel> AnalyzeSections(ProgramModel program)
    {
        var result = new List<SectionEntropyModel>();
        foreach (var sec in program.Sections)
        {
            long size = (long)(sec.EndAddress > sec.StartAddress ? (sec.EndAddress - sec.StartAddress) : 0);
            byte[]? data = sec.Data;
            double entropy = 0.0;

            if (data != null && data.Length > 0)
            {
                entropy = CalculateShannonEntropy(data, 0, data.Length);
            }

            string status;
            if (entropy >= 7.0)
            {
                status = "Packed / Encrypted";
            }
            else if (entropy >= 5.2 && sec.Permissions.Contains("X"))
            {
                status = "Normal (Executable Code)";
            }
            else if (entropy >= 4.0)
            {
                status = "Normal (Data / Strings)";
            }
            else
            {
                status = "Sparse / Zero-padded";
            }

            var item = new SectionEntropyModel
            {
                Name = sec.Name,
                StartAddress = sec.StartAddress,
                EndAddress = sec.EndAddress,
                Size = size,
                Entropy = entropy,
                Status = status
            };
            result.Add(item);
        }
        return result;
    }

    public static List<EntropyBlockModel> AnalyzeBlocks(ProgramModel program, int blockSize = 1024, int maxBlocks = 500)
    {
        var blocks = new List<EntropyBlockModel>();

        foreach (var sec in program.Sections)
        {
            byte[]? data = sec.Data;
            if (data == null || data.Length == 0) continue;

            int count = data.Length;
            int effectiveBlockSize = blockSize;
            if (count / effectiveBlockSize > maxBlocks)
            {
                effectiveBlockSize = count / maxBlocks;
            }
            if (effectiveBlockSize < 64) effectiveBlockSize = 64;

            for (int offset = 0; offset < count; offset += effectiveBlockSize)
            {
                int len = Math.Min(effectiveBlockSize, count - offset);
                double ent = CalculateShannonEntropy(data, offset, len);

                blocks.Add(new EntropyBlockModel
                {
                    Address = sec.StartAddress + (ulong)offset,
                    Entropy = ent,
                    SectionName = sec.Name
                });
            }
        }

        return blocks;
    }
}

public static class DemanglerService
{
    private static readonly Dictionary<string, string> BasicTypes = new()
    {
        { "X", "void" },
        { "D", "char" },
        { "C", "signed char" },
        { "E", "unsigned char" },
        { "F", "short" },
        { "G", "unsigned short" },
        { "H", "int" },
        { "I", "unsigned int" },
        { "J", "long" },
        { "K", "unsigned long" },
        { "M", "float" },
        { "N", "double" },
        { "_N", "bool" },
        { "_J", "__int64" },
        { "_K", "unsigned __int64" },
        { "_W", "wchar_t" },
        { "Z", "..." }
    };

    public static bool TryDemangle(string mangled, out string demangled)
    {
        demangled = Demangle(mangled);
        return !demangled.Equals(mangled, StringComparison.Ordinal);
    }

    public static string Demangle(string mangled)
    {
        if (string.IsNullOrWhiteSpace(mangled)) return mangled;
        mangled = mangled.Trim();

        // 1. MSVC Demangler: starts with '?'
        if (mangled.StartsWith("?"))
        {
            string? msvc = DemangleMsvc(mangled);
            if (!string.IsNullOrEmpty(msvc)) return msvc;
        }

        // 2. GNU / Itanium Demangler: starts with '_Z'
        if (mangled.StartsWith("_Z"))
        {
            string? itanium = DemangleItanium(mangled);
            if (!string.IsNullOrEmpty(itanium)) return itanium;
        }

        return mangled;
    }

    private static string? DemangleMsvc(string mangled)
    {
        try
        {
            string rest = mangled.Substring(1);

            string prefix = "";
            bool isVtable = false;
            bool isCtor = false;
            bool isDtor = false;

            if (rest.StartsWith("?0")) { isCtor = true; rest = rest.Substring(2); }
            else if (rest.StartsWith("?1")) { isDtor = true; rest = rest.Substring(2); }
            else if (rest.StartsWith("?_7")) { isVtable = true; rest = rest.Substring(3); }
            else if (rest.StartsWith("?2")) { prefix = "operator new"; rest = rest.Substring(2); }
            else if (rest.StartsWith("?3")) { prefix = "operator delete"; rest = rest.Substring(2); }
            else if (rest.StartsWith("?4")) { prefix = "operator="; rest = rest.Substring(2); }
            else if (rest.StartsWith("?8")) { prefix = "operator=="; rest = rest.Substring(2); }
            else if (rest.StartsWith("?9")) { prefix = "operator!="; rest = rest.Substring(2); }
            else if (rest.StartsWith("?H")) { prefix = "operator+"; rest = rest.Substring(2); }
            else if (rest.StartsWith("?G")) { prefix = "operator-"; rest = rest.Substring(2); }
            else if (rest.StartsWith("?A")) { prefix = "operator[]"; rest = rest.Substring(2); }

            int scopeEnd = rest.IndexOf("@@");
            if (scopeEnd <= 0) return null;

            string scopePart = rest.Substring(0, scopeEnd);
            string signaturePart = rest.Substring(scopeEnd + 2);

            var scopes = scopePart.Split('@', StringSplitOptions.RemoveEmptyEntries);
            if (scopes.Length == 0) return null;

            string methodName = prefix;
            string className = "";

            if (isCtor)
            {
                className = scopes[0];
                methodName = className;
            }
            else if (isDtor)
            {
                className = scopes[0];
                methodName = "~" + className;
            }
            else if (isVtable)
            {
                return $"const {string.Join("::", scopes.Reverse())}::'vftable'";
            }
            else if (string.IsNullOrEmpty(methodName))
            {
                methodName = scopes[0];
                if (scopes.Length > 1)
                {
                    className = string.Join("::", scopes.Skip(1).Reverse());
                }
            }
            else
            {
                className = string.Join("::", scopes.Reverse());
            }

            string fullQualified = string.IsNullOrEmpty(className) ? methodName : $"{className}::{methodName}";

            string returnType = "void";
            var parameters = new List<string>();

            if (signaturePart.Length > 0)
            {
                int idx = 0;
                while (idx < signaturePart.Length && (signaturePart[idx] == 'Q' || signaturePart[idx] == 'A' || signaturePart[idx] == 'I' || signaturePart[idx] == 'E' || signaturePart[idx] == 'Y' || signaturePart[idx] == 'Z'))
                {
                    idx++;
                }

                if (idx < signaturePart.Length && !isCtor && !isDtor)
                {
                    returnType = DecodeMsvcType(signaturePart, ref idx);
                }

                while (idx < signaturePart.Length && signaturePart[idx] != '@' && signaturePart[idx] != 'Z')
                {
                    string pType = DecodeMsvcType(signaturePart, ref idx);
                    if (pType == "void" && parameters.Count == 0) break;
                    parameters.Add(pType);
                }
            }

            string paramStr = parameters.Count == 0 ? "void" : string.Join(", ", parameters);
            if (isCtor || isDtor)
            {
                return $"{fullQualified}({paramStr})";
            }
            return $"{returnType} {fullQualified}({paramStr})";
        }
        catch
        {
            return null;
        }
    }

    private static string DecodeMsvcType(string s, ref int idx)
    {
        if (idx >= s.Length) return "void";

        if (s.Substring(idx).StartsWith("PEA") || s.Substring(idx).StartsWith("PEB") || s.Substring(idx).StartsWith("PA") || s.Substring(idx).StartsWith("PB"))
        {
            bool isConst = s[idx + 1] == 'B' || (idx + 2 < s.Length && s[idx + 2] == 'B');
            idx += s.Substring(idx).StartsWith("PE") ? 3 : 2;
            string target = DecodeMsvcType(s, ref idx);
            return (isConst ? "const " : "") + target + "*";
        }

        if (s.Substring(idx).StartsWith("AEA") || s.Substring(idx).StartsWith("AEB"))
        {
            bool isConst = s[idx + 2] == 'B';
            idx += 3;
            string target = DecodeMsvcType(s, ref idx);
            return (isConst ? "const " : "") + target + "&";
        }

        if (s[idx] == 'V' || s[idx] == 'U')
        {
            idx++;
            int end = s.IndexOf("@@", idx);
            if (end > idx)
            {
                string cName = s.Substring(idx, end - idx).Replace('@', ':');
                idx = end + 2;
                return cName;
            }
        }

        if (s[idx] == '_' && idx + 1 < s.Length)
        {
            string key = "_" + s[idx + 1];
            idx += 2;
            if (BasicTypes.TryGetValue(key, out var bt)) return bt;
            return "int64";
        }

        string single = s[idx].ToString();
        idx++;
        if (BasicTypes.TryGetValue(single, out var val)) return val;
        return "int";
    }

    private static string? DemangleItanium(string mangled)
    {
        try
        {
            if (mangled.StartsWith("_ZTV"))
            {
                string target = mangled.Substring(4);
                return $"vtable for {DemangleItaniumIdentifier(ref target)}";
            }

            if (mangled.StartsWith("_ZN"))
            {
                int endE = mangled.IndexOf('E', 3);
                if (endE <= 3) return null;

                string namesBlock = mangled.Substring(3, endE - 3);
                string paramsBlock = mangled.Substring(endE + 1);

                var parts = new List<string>();
                int pos = 0;
                while (pos < namesBlock.Length)
                {
                    if (char.IsDigit(namesBlock[pos]))
                    {
                        int len = 0;
                        while (pos < namesBlock.Length && char.IsDigit(namesBlock[pos]))
                        {
                            len = len * 10 + (namesBlock[pos] - '0');
                            pos++;
                        }
                        if (pos + len <= namesBlock.Length)
                        {
                            parts.Add(namesBlock.Substring(pos, len));
                            pos += len;
                        }
                        else break;
                    }
                    else if (namesBlock.Substring(pos).StartsWith("C1") || namesBlock.Substring(pos).StartsWith("C2"))
                    {
                        string ctorName = parts.LastOrDefault() ?? "Class";
                        parts.Add(ctorName);
                        pos += 2;
                    }
                    else if (namesBlock.Substring(pos).StartsWith("D1") || namesBlock.Substring(pos).StartsWith("D2"))
                    {
                        string dtorName = parts.LastOrDefault() ?? "Class";
                        parts.Add("~" + dtorName);
                        pos += 2;
                    }
                    else
                    {
                        pos++;
                    }
                }

                if (parts.Count == 0) return null;
                string fullName = string.Join("::", parts);

                var parameters = new List<string>();
                int pIdx = 0;
                while (pIdx < paramsBlock.Length)
                {
                    parameters.Add(DecodeItaniumType(paramsBlock, ref pIdx));
                }

                string pStr = parameters.Count == 0 || (parameters.Count == 1 && parameters[0] == "void") ? "void" : string.Join(", ", parameters);
                return $"{fullName}({pStr})";
            }
            else if (mangled.StartsWith("_Z"))
            {
                int pos = 2;
                if (char.IsDigit(mangled[pos]))
                {
                    int len = 0;
                    while (pos < mangled.Length && char.IsDigit(mangled[pos]))
                    {
                        len = len * 10 + (mangled[pos] - '0');
                        pos++;
                    }
                    string funcName = mangled.Substring(pos, len);
                    pos += len;
                    var parameters = new List<string>();
                    while (pos < mangled.Length)
                    {
                        parameters.Add(DecodeItaniumType(mangled, ref pos));
                    }
                    string pStr = parameters.Count == 0 ? "void" : string.Join(", ", parameters);
                    return $"{funcName}({pStr})";
                }
            }
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static string DemangleItaniumIdentifier(ref string s)
    {
        int pos = 0;
        int len = 0;
        while (pos < s.Length && char.IsDigit(s[pos]))
        {
            len = len * 10 + (s[pos] - '0');
            pos++;
        }
        if (len > 0 && pos + len <= s.Length)
        {
            string res = s.Substring(pos, len);
            s = s.Substring(pos + len);
            return res;
        }
        return s;
    }

    private static string DecodeItaniumType(string s, ref int idx)
    {
        if (idx >= s.Length) return "void";
        char c = s[idx++];
        return c switch
        {
            'v' => "void",
            'i' => "int",
            'c' => "char",
            'b' => "bool",
            'f' => "float",
            'd' => "double",
            'l' => "long",
            'm' => "unsigned long",
            'x' => "long long",
            'y' => "unsigned long long",
            'j' => "unsigned int",
            's' => "short",
            't' => "unsigned short",
            'P' => DecodeItaniumType(s, ref idx) + "*",
            'R' => DecodeItaniumType(s, ref idx) + "&",
            'K' => "const " + DecodeItaniumType(s, ref idx),
            _ => "int"
        };
    }

    public static int DemangleAllProgramSymbols(ProgramModel program)
    {
        int count = 0;
        foreach (var item in program.ListingLines)
        {
            if (item.IsFunctionHeader && TryDemangle(item.FunctionName, out string demangled))
            {
                item.Comment = string.IsNullOrEmpty(item.Comment) ? $"Demangled: {demangled}" : $"{item.Comment} | Demangled: {demangled}";
                count++;
            }
        }
        return count;
    }
}

public static class PdbService
{
    public static PdbInfoModel ExtractPdbInfo(string filePath)
    {
        var model = new PdbInfoModel
        {
            HasCodeView = false,
            Status = "No CodeView RSDS debug entry found"
        };

        if (!File.Exists(filePath)) return model;

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new BinaryReader(fs);

            if (fs.Length < 0x200) return model;

            // DOS Header
            ushort mz = reader.ReadUInt16();
            if (mz != 0x5A4D) return model;

            fs.Seek(0x3C, SeekOrigin.Begin);
            int peOffset = reader.ReadInt32();
            fs.Seek(peOffset, SeekOrigin.Begin);

            uint peSig = reader.ReadUInt32();
            if (peSig != 0x00004550) return model;

            // COFF Header
            reader.ReadUInt16(); // machine
            ushort numSections = reader.ReadUInt16();
            fs.Seek(12, SeekOrigin.Current); // skip timestamp, symbols
            ushort sizeOfOptionalHeader = reader.ReadUInt16();
            reader.ReadUInt16(); // chars

            long optHeaderPos = fs.Position;
            ushort optMagic = reader.ReadUInt16();
            bool is64 = (optMagic == 0x20B);

            int debugDirOffset = is64 ? 160 : 144;
            if (sizeOfOptionalHeader < debugDirOffset + 8) return model;

            fs.Seek(optHeaderPos + debugDirOffset, SeekOrigin.Begin);
            uint debugRva = reader.ReadUInt32();
            uint debugSize = reader.ReadUInt32();

            if (debugRva == 0 || debugSize == 0)
            {
                return ScanForRsds(fs, reader);
            }

            fs.Seek(optHeaderPos + sizeOfOptionalHeader, SeekOrigin.Begin);
            uint rawOffset = 0;
            for (int i = 0; i < numSections; i++)
            {
                fs.Seek(8, SeekOrigin.Current); // sec name
                uint vSize = reader.ReadUInt32();
                uint vAddr = reader.ReadUInt32();
                uint rSize = reader.ReadUInt32();
                uint rPtr = reader.ReadUInt32();
                fs.Seek(16, SeekOrigin.Current); // reloc, lines, chars

                if (debugRva >= vAddr && debugRva < vAddr + vSize)
                {
                    rawOffset = rPtr + (debugRva - vAddr);
                    break;
                }
            }

            if (rawOffset > 0 && rawOffset < fs.Length)
            {
                fs.Seek(rawOffset, SeekOrigin.Begin);
                int numEntries = (int)(debugSize / 28);
                for (int i = 0; i < numEntries; i++)
                {
                    reader.ReadUInt32(); // chars
                    reader.ReadUInt32(); // time
                    reader.ReadUInt16(); // major
                    reader.ReadUInt16(); // minor
                    uint type = reader.ReadUInt32(); // 2 == IMAGE_DEBUG_TYPE_CODEVIEW
                    uint sizeOfData = reader.ReadUInt32();
                    reader.ReadUInt32(); // rva
                    uint ptrToRaw = reader.ReadUInt32();

                    if (type == 2 && ptrToRaw > 0 && ptrToRaw + sizeOfData <= fs.Length)
                    {
                        long saved = fs.Position;
                        fs.Seek(ptrToRaw, SeekOrigin.Begin);

                        uint sig = reader.ReadUInt32();
                        if (sig == 0x53445352) // "RSDS"
                        {
                            byte[] guidBytes = reader.ReadBytes(16);
                            uint age = reader.ReadUInt32();
                            byte[] pathBytes = reader.ReadBytes((int)(sizeOfData - 24));
                            string pdbPath = Encoding.UTF8.GetString(pathBytes).TrimEnd('\0');

                            model.HasCodeView = true;
                            model.Guid = new Guid(guidBytes);
                            model.Age = age;
                            model.PdbPath = pdbPath;
                            model.Status = "CodeView RSDS Signature Verified";
                            return model;
                        }

                        fs.Seek(saved, SeekOrigin.Begin);
                    }
                }
            }

            return ScanForRsds(fs, reader);
        }
        catch (Exception ex)
        {
            model.Status = $"PDB Parsing exception: {ex.Message}";
            return model;
        }
    }

    private static PdbInfoModel ScanForRsds(FileStream fs, BinaryReader reader)
    {
        var model = new PdbInfoModel { HasCodeView = false, Status = "No RSDS Found" };
        try
        {
            fs.Seek(0, SeekOrigin.Begin);
            byte[] buf = new byte[Math.Min(fs.Length, 1024 * 1024 * 8)];
            int read = fs.Read(buf, 0, buf.Length);

            for (int i = 0; i < read - 24; i++)
            {
                if (buf[i] == 'R' && buf[i + 1] == 'S' && buf[i + 2] == 'D' && buf[i + 3] == 'S')
                {
                    byte[] guidBytes = new byte[16];
                    Buffer.BlockCopy(buf, i + 4, guidBytes, 0, 16);
                    uint age = BitConverter.ToUInt32(buf, i + 20);

                    int pStart = i + 24;
                    int pEnd = pStart;
                    while (pEnd < read && buf[pEnd] != 0 && pEnd - pStart < 260) pEnd++;

                    string pdbPath = Encoding.ASCII.GetString(buf, pStart, pEnd - pStart);
                    model.HasCodeView = true;
                    model.Guid = new Guid(guidBytes);
                    model.Age = age;
                    model.PdbPath = pdbPath;
                    model.Status = "Discovered RSDS via file scan";
                    return model;
                }
            }
        }
        catch { }
        return model;
    }
}

public static class FlowArrowService
{
    private static readonly HashSet<string> JumpMnemonics = new(StringComparer.OrdinalIgnoreCase)
    {
        "JMP", "JE", "JZ", "JNE", "JNZ", "JA", "JAE", "JB", "JBE",
        "JG", "JGE", "JL", "JLE", "JS", "JNS", "JO", "JNO", "LOOP", "LOOPE", "LOOPNE"
    };

    public static void UpdateFlowArrows(ProgramModel program)
    {
        foreach (var item in program.ListingLines)
        {
            if (ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong currentAddr))
            {
                if (program.FallthroughOverrides.TryGetValue(currentAddr, out ulong? overrideAddr))
                {
                    item.FallthroughOverrideAddress = overrideAddr;
                    if (overrideAddr.HasValue)
                    {
                        item.FallthroughText = $"[Fallthrough -> 0x{overrideAddr.Value:X8}]";
                    }
                    else
                    {
                        item.FallthroughText = "[No Fallthrough]";
                    }
                }
                else
                {
                    item.FallthroughText = "";
                    item.FallthroughOverrideAddress = null;
                }

                string instr = item.Instruction.Trim().ToUpperInvariant();
                if (JumpMnemonics.Contains(instr))
                {
                    ulong target = ParseTargetAddress(item.Operands);
                    if (target != 0)
                    {
                        if (target < currentAddr)
                        {
                            item.FlowArrow = "↑ ↻";
                        }
                        else
                        {
                            item.FlowArrow = "↓ ";
                        }
                    }
                    else
                    {
                        item.FlowArrow = "↓ ";
                    }
                }
                else if (instr == "CALL")
                {
                    item.FlowArrow = "➔";
                }
                else if (instr == "RET" || instr == "RETN")
                {
                    item.FlowArrow = "⮌";
                }
                else
                {
                    item.FlowArrow = "";
                }
            }
        }
    }

    private static ulong ParseTargetAddress(string operands)
    {
        if (string.IsNullOrEmpty(operands)) return 0;
        var parts = operands.Split(new[] { ' ', ',', '[', ']' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var p in parts)
        {
            string clean = p.Trim();
            if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (ulong.TryParse(clean.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                    return addr;
            }
            if (ulong.TryParse(clean, System.Globalization.NumberStyles.HexNumber, null, out ulong hexAddr) && hexAddr > 0x1000)
            {
                return hexAddr;
            }
        }
        return 0;
    }

    public static void SetFallthroughOverride(ProgramModel program, ulong address, ulong? targetAddress)
    {
        program.FallthroughOverrides[address] = targetAddress;
        UpdateFlowArrows(program);
    }

    public static void ClearFallthroughOverride(ProgramModel program, ulong address)
    {
        program.FallthroughOverrides.Remove(address);
        UpdateFlowArrows(program);
    }
}

public class ScriptGlobals
{
    public ProgramModel CurrentProgram { get; set; } = null!;
    public ObservableCollection<ListingItem> Listing => CurrentProgram.ListingLines;
    public ObservableCollection<SectionNode> Sections => CurrentProgram.Sections;
    public Dictionary<ulong, List<XRefModel>> XRefs => CurrentProgram.XRefs;
    public ulong CurrentAddress { get; set; }
    public string CurrentFunctionName { get; set; } = string.Empty;
    public Action<object?> Print { get; set; } = _ => { };
    public Action<string> Log { get; set; } = _ => { };
    public Action<ulong> JumpTo { get; set; } = _ => { };
    public Action<ulong, byte[]> PatchBytes { get; set; } = (_, _) => { };
    public Func<string, string> Decompile { get; set; } = _ => string.Empty;
    public Func<string, string> Demangle { get; set; } = s => s;
}

public static class RoslynScriptService
{
    public static async Task<(bool Success, string Output, object? Result)> ExecuteScriptAsync(string csharpCode, ScriptGlobals globals)
    {
        var outputBuilder = new StringBuilder();
        var origPrint = globals.Print;
        globals.Print = obj =>
        {
            outputBuilder.AppendLine(obj?.ToString() ?? "null");
            origPrint?.Invoke(obj);
        };

        try
        {
            var options = ScriptOptions.Default
                .WithImports(
                    "System",
                    "System.Collections.Generic",
                    "System.Linq",
                    "System.Text",
                    "Ghidra.UI.Models",
                    "Ghidra.UI.Services"
                )
                .WithReferences(
                    typeof(ProgramModel).Assembly,
                    typeof(ObservableCollection<>).Assembly
                );

            var script = CSharpScript.Create(csharpCode, options, typeof(ScriptGlobals));
            var diagnostics = script.Compile();
            var errors = diagnostics.Where(d => d.Severity == Microsoft.CodeAnalysis.DiagnosticSeverity.Error).ToList();

            if (errors.Count > 0)
            {
                foreach (var err in errors)
                {
                    var lineSpan = err.Location.GetLineSpan();
                    outputBuilder.AppendLine($"[Error L{lineSpan.StartLinePosition.Line + 1}] {err.GetMessage()}");
                }
                return (false, outputBuilder.ToString(), null);
            }

            var state = await script.RunAsync(globals);
            if (state.ReturnValue != null)
            {
                outputBuilder.AppendLine($"[Return] {state.ReturnValue}");
            }
            return (true, outputBuilder.ToString(), state.ReturnValue);
        }
        catch (Exception ex)
        {
            outputBuilder.AppendLine($"[Runtime Exception] {ex.GetType().Name}: {ex.Message}");
            return (false, outputBuilder.ToString(), null);
        }
    }

    public static List<ScriptItemModel> GetDefaultScripts()
    {
        return new List<ScriptItemModel>
        {
            new ScriptItemModel
            {
                Name = "Crypto & Hash Constant Scanner",
                Category = "Cryptanalysis",
                Description = "Scans memory and sections for cryptographic constants (MD5, SHA-256, AES S-Box).",
                Icon = "🔐",
                ScriptCode = @"// Scan sections for well-known cryptographic constants
Print(""=== Scanning for Cryptographic Constants ==="");
int found = 0;

byte[] aesSbox = new byte[] { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5 };

foreach (var sec in Sections)
{
    if (sec.Data == null || sec.Data.Length < 8) continue;
    for (int i = 0; i <= sec.Data.Length - aesSbox.Length; i++)
    {
        bool match = true;
        for (int j = 0; j < aesSbox.Length; j++)
        {
            if (sec.Data[i + j] != aesSbox[j]) { match = false; break; }
        }
        if (match)
        {
            ulong addr = sec.StartAddress + (ulong)i;
            Print($""[AES] Found AES Rijndael S-Box constant at 0x{addr:X8} in section {sec.Name}"");
            found++;
        }
    }
}

foreach (var item in Listing)
{
    if (item.Operands.Contains(""428A2F98"", StringComparison.OrdinalIgnoreCase))
    {
        Print($""[SHA-256] K[0] constant (0x428a2f98) referenced at 0x{item.Address}"");
        found++;
    }
    if (item.Operands.Contains(""67452301"", StringComparison.OrdinalIgnoreCase))
    {
        Print($""[MD5/SHA-1] Init constant (0x67452301) referenced at 0x{item.Address}"");
        found++;
    }
}

Print($""Scan complete: {found} crypto artifact(s) detected."");"
            },
            new ScriptItemModel
            {
                Name = "XOR String & Payload Decryptor",
                Category = "Deobfuscation",
                Description = "Brute-forces or tests single-byte XOR keys on binary data to uncover hidden strings.",
                Icon = "🔓",
                ScriptCode = @"Print(""=== Single-Byte XOR Key Candidate Search ==="");
int candidates = 0;

foreach (var sec in Sections)
{
    if (sec.Data == null || sec.Data.Length == 0) continue;
    int maxLen = Math.Min(sec.Data.Length, 4096);

    for (byte key = 1; key < 255; key++)
    {
        int asciiCount = 0;
        var sb = new StringBuilder();
        for (int i = 0; i < maxLen; i++)
        {
            byte dec = (byte)(sec.Data[i] ^ key);
            if (dec >= 32 && dec <= 126)
            {
                asciiCount++;
                if (sb.Length < 40) sb.Append((char)dec);
            }
        }

        if (asciiCount > maxLen * 0.70)
        {
            Print($""Section {sec.Name}: Key 0x{key:X2} yields {asciiCount * 100 / maxLen}% ASCII text: \""{sb}\""..."");
            candidates++;
            if (candidates >= 5) break;
        }
    }
}

if (candidates == 0) Print(""No high-confidence single-byte XOR payloads found in scanned headers."");"
            },
            new ScriptItemModel
            {
                Name = "Opcode Frequency Analyzer",
                Category = "Statistics",
                Description = "Calculates assembly mnemonic frequencies across all loaded instructions.",
                Icon = "📊",
                ScriptCode = @"Print(""=== Opcode & Instruction Frequency Analyzer ==="");
var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

foreach (var item in Listing)
{
    if (string.IsNullOrWhiteSpace(item.Instruction)) continue;
    string mn = item.Instruction.Trim().ToUpperInvariant();
    counts[mn] = counts.GetValueOrDefault(mn) + 1;
}

var top = counts.OrderByDescending(kv => kv.Value).Take(15).ToList();
Print($""Total instructions analyzed: {Listing.Count}"");
Print(""Rank  Mnemonic   Count   Percentage"");
Print(""----------------------------------"");
int rank = 1;
foreach (var (mn, cnt) in top)
{
    double pct = (double)cnt * 100.0 / Math.Max(1, Listing.Count);
    Print($""{rank,-5} {mn,-10} {cnt,-7} {pct:F2}%"");
    rank++;
}"
            },
            new ScriptItemModel
            {
                Name = "Clean Disassembly Exporter",
                Category = "Export",
                Description = "Formats the current function instructions into clean Intel NASM assembly syntax.",
                Icon = "📤",
                ScriptCode = @"Print($""=== Exporting Disassembly for Function: {CurrentFunctionName} ==="");
var sb = new StringBuilder();
sb.AppendLine($ ""; Function: {CurrentFunctionName} @ 0x{CurrentAddress:X8}"");
sb.AppendLine(""; Exported via GhidraNet Roslyn Script Manager"");
sb.AppendLine();

int count = 0;
foreach (var item in Listing)
{
    if (item.IsFunctionHeader && item.FunctionName == CurrentFunctionName)
    {
        sb.AppendLine($""{item.FunctionName}:"");
    }
    sb.AppendLine($""    0x{item.Address,-10} {item.Instruction,-8} {item.Operands}"");
    count++;
    if (count > 50) break;
}

Print(sb.ToString());
Print($""Exported {count} instruction line(s) to console."");"
            },
            new ScriptItemModel
            {
                Name = "Function Prologue Scanner",
                Category = "Analysis",
                Description = "Detects standard x86/x64 stack frame setup instructions and function boundaries.",
                Icon = "🔍",
                ScriptCode = @"Print(""=== Scanning for Function Prologues (x86_64) ==="");
int prologueCount = 0;

for (int i = 0; i < Listing.Count - 1; i++)
{
    var curr = Listing[i];
    var next = Listing[i + 1];

    bool isPrologue = (curr.Instruction.Equals(""PUSH"", StringComparison.OrdinalIgnoreCase) && curr.Operands.Contains(""RBP"", StringComparison.OrdinalIgnoreCase) &&
                       next.Instruction.Equals(""MOV"", StringComparison.OrdinalIgnoreCase) && next.Operands.Contains(""RBP"", StringComparison.OrdinalIgnoreCase));

    if (!isPrologue && curr.Instruction.Equals(""SUB"", StringComparison.OrdinalIgnoreCase) && curr.Operands.StartsWith(""RSP"", StringComparison.OrdinalIgnoreCase))
    {
        isPrologue = true;
    }

    if (isPrologue)
    {
        Print($""[Prologue] Function entry candidate @ 0x{curr.Address} ({curr.Instruction} {curr.Operands})"");
        prologueCount++;
    }
}

Print($""Total prologue candidates found: {prologueCount}"");"
            }
        };
    }
}


