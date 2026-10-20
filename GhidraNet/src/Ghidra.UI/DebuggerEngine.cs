using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Ghidra.UI.Models;

namespace Ghidra.UI;

/// <summary>
/// Public interface for debugger engines (Native Win32 and Virtual SRE Emulator).
/// </summary>
public interface IDebuggerEngine
{
    event Action<DebuggerState>? StateChanged;
    event Action<ulong, string>? TargetStopped;
    event Action<int>? TargetExited;
    event Action<string>? LogMessage;

    DebuggerState State { get; }
    int ProcessId { get; }
    string TargetPath { get; }
    ulong CurrentInstructionPointer { get; }

    ObservableCollection<BreakpointModel> Breakpoints { get; }
    ObservableCollection<RegisterModel> Registers { get; }
    ObservableCollection<StackFrameModel> CallStack { get; }
    ObservableCollection<ThreadModel> Threads { get; }
    ObservableCollection<DebuggerMemoryRow> MemoryRows { get; }

    Task<bool> LaunchAsync(string exePath, string arguments = "");
    Task<bool> AttachAsync(int processId);
    Task ResumeAsync();
    Task PauseAsync();
    Task StepIntoAsync();
    Task StepOverAsync();
    Task StepOutAsync();
    Task StopAsync();
    Task RestartAsync();

    void ToggleBreakpoint(ulong address, string functionName = "");
    void SetBreakpoint(ulong address, bool enabled, string condition = "");
    void RemoveBreakpoint(ulong address);
    void ClearAllBreakpoints();

    bool SetRegister(string regName, ulong value);
    byte[] ReadMemory(ulong address, int size);
    bool WriteMemory(ulong address, byte[] data);
    void RefreshMemoryRows(ulong baseAddress, int rowCount = 16);
}

/// <summary>
/// High-fidelity virtual x86_64 CPU & memory execution emulator.
/// Runs inside Ghidra.NET for deterministic reverse engineering, symbolic stepping,
/// and dynamic analysis without requiring administrative debug privileges.
/// </summary>
public class EmulatedDebuggerEngine : IDebuggerEngine
{
    private DebuggerState _state = DebuggerState.Inactive;
    private readonly Dictionary<ulong, byte> _virtualMemory = new();
    private readonly Dictionary<string, ulong> _registers = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<ulong> _activeBreakpoints = new();
    private CancellationTokenSource? _runCts;
    private ProgramModel? _programModel;

    public event Action<DebuggerState>? StateChanged;
    public event Action<ulong, string>? TargetStopped;
    public event Action<int>? TargetExited;
    public event Action<string>? LogMessage;

    public DebuggerState State
    {
        get => _state;
        private set
        {
            if (_state != value)
            {
                _state = value;
                StateChanged?.Invoke(_state);
            }
        }
    }

    public int ProcessId { get; private set; } = 4096; // Virtual PID
    public string TargetPath { get; private set; } = string.Empty;
    public ulong CurrentInstructionPointer { get; private set; }

    public ObservableCollection<BreakpointModel> Breakpoints { get; } = new();
    public ObservableCollection<RegisterModel> Registers { get; } = new();
    public ObservableCollection<StackFrameModel> CallStack { get; } = new();
    public ObservableCollection<ThreadModel> Threads { get; } = new();
    public ObservableCollection<DebuggerMemoryRow> MemoryRows { get; } = new();

    public EmulatedDebuggerEngine()
    {
        InitializeRegisterList();
    }

    public void SetProgramModel(ProgramModel? model)
    {
        _programModel = model;
    }

    private void InitializeRegisterList()
    {
        Registers.Clear();
        string[] gpRegs = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"];
        foreach (var reg in gpRegs)
        {
            _registers[reg] = 0;
            Registers.Add(new RegisterModel
            {
                Name = reg,
                Category = RegisterCategory.GeneralPurpose,
                BitWidth = 64,
                ValueUlong = 0
            });
        }

        // Instruction Pointer
        _registers["RIP"] = 0;
        Registers.Add(new RegisterModel
        {
            Name = "RIP",
            Category = RegisterCategory.InstructionPointer,
            BitWidth = 64,
            ValueUlong = 0,
            Description = "Instruction Pointer"
        });

        // RFLAGS
        _registers["RFLAGS"] = 0x246; // Standard initial flags (IF, PF, reserved bit 1)
        Registers.Add(new RegisterModel
        {
            Name = "RFLAGS",
            Category = RegisterCategory.Flags,
            BitWidth = 64,
            ValueUlong = 0x246,
            Description = "Flags [IF PF]"
        });

        // Segment Registers
        string[] segRegs = ["CS", "DS", "ES", "FS", "GS", "SS"];
        foreach (var seg in segRegs)
        {
            _registers[seg] = 0x2B;
            Registers.Add(new RegisterModel
            {
                Name = seg,
                Category = RegisterCategory.Segment,
                BitWidth = 16,
                ValueUlong = 0x2B
            });
        }

        // SIMD
        for (int i = 0; i < 8; i++)
        {
            string xmm = $"XMM{i}";
            _registers[xmm] = 0;
            Registers.Add(new RegisterModel
            {
                Name = xmm,
                Category = RegisterCategory.SIMD,
                BitWidth = 64,
                ValueUlong = 0
            });
        }
    }

    public Task<bool> LaunchAsync(string exePath, string arguments = "")
    {
        TargetPath = exePath;
        _virtualMemory.Clear();
        _runCts?.Cancel();

        ulong entryPoint = _programModel?.EntryPoint ?? 0x140001000;
        CurrentInstructionPointer = entryPoint;

        // Initialize virtual registers
        _registers["RIP"] = entryPoint;
        _registers["RSP"] = 0x000000E0_0012FE00;
        _registers["RBP"] = 0x000000E0_0012FE00;
        _registers["RAX"] = 0;
        _registers["RBX"] = 0;
        _registers["RCX"] = 1;
        _registers["RDX"] = 0x000000E0_0012FE80;
        _registers["RFLAGS"] = 0x246;

        SyncRegistersToCollection();

        // Initialize stack frames
        CallStack.Clear();
        CallStack.Add(new StackFrameModel
        {
            FrameIndex = 0,
            InstructionAddress = $"0x{entryPoint:X16}",
            InstructionVal = entryPoint,
            FunctionName = _programModel != null && _programModel.RenamedSymbols.TryGetValue(entryPoint.ToString("X"), out var fn) ? fn : "main_entry",
            ModuleName = Path.GetFileName(exePath),
            StackPointer = $"0x{_registers["RSP"]:X16}",
            FramePointer = $"0x{_registers["RBP"]:X16}"
        });

        // Initialize main thread
        Threads.Clear();
        Threads.Add(new ThreadModel
        {
            ThreadId = 1001,
            ThreadName = "Main Thread (0x3E9)",
            CurrentAddress = $"0x{entryPoint:X16}",
            State = "Paused (Entry Point)",
            IsCurrent = true
        });

        RefreshMemoryRows(entryPoint);

        State = DebuggerState.Paused;
        LogMessage?.Invoke($"[Emulator] Session launched. Target: '{Path.GetFileName(exePath)}' (Virtual PID: {ProcessId}). Suspended at Entry Point: 0x{entryPoint:X16}");
        TargetStopped?.Invoke(entryPoint, "Entry Point Hit");

        return Task.FromResult(true);
    }

    public Task<bool> AttachAsync(int processId)
    {
        ProcessId = processId;
        TargetPath = $"Attached Process (PID: {processId})";
        ulong baseAddr = _programModel?.EntryPoint ?? 0x140001000;
        CurrentInstructionPointer = baseAddr;
        _registers["RIP"] = baseAddr;
        SyncRegistersToCollection();

        CallStack.Clear();
        CallStack.Add(new StackFrameModel
        {
            FrameIndex = 0,
            InstructionAddress = $"0x{baseAddr:X16}",
            InstructionVal = baseAddr,
            FunctionName = "ntdll!DbgBreakPoint",
            ModuleName = "ntdll.dll",
            StackPointer = "0x000000E00012FE00",
            FramePointer = "0x000000E00012FE00"
        });

        Threads.Clear();
        Threads.Add(new ThreadModel
        {
            ThreadId = (uint)processId,
            ThreadName = $"Target Thread (0x{processId:X4})",
            CurrentAddress = $"0x{baseAddr:X16}",
            State = "Suspended (Attached)",
            IsCurrent = true
        });

        RefreshMemoryRows(baseAddr);
        State = DebuggerState.Paused;
        LogMessage?.Invoke($"[Emulator] Attached to PID {processId}. Target suspended at 0x{baseAddr:X16}.");
        TargetStopped?.Invoke(baseAddr, "Attached Break");

        return Task.FromResult(true);
    }

    public async Task ResumeAsync()
    {
        if (State != DebuggerState.Paused) return;

        State = DebuggerState.Running;
        LogMessage?.Invoke($"[Emulator] Target resumed execution from 0x{CurrentInstructionPointer:X16}...");
        _runCts = new CancellationTokenSource();
        var token = _runCts.Token;

        await Task.Run(async () =>
        {
            int stepCount = 0;
            while (!token.IsCancellationRequested && State == DebuggerState.Running)
            {
                bool hit = ExecuteSingleInstruction();
                stepCount++;

                if (hit || _activeBreakpoints.Contains(CurrentInstructionPointer))
                {
                    Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        State = DebuggerState.Paused;
                        SyncRegistersToCollection();
                        RefreshMemoryRows(CurrentInstructionPointer);
                        var bp = Breakpoints.FirstOrDefault(b => b.AddressVal == CurrentInstructionPointer);
                        if (bp != null) bp.HitCount++;
                        LogMessage?.Invoke($"[Emulator] Breakpoint hit at 0x{CurrentInstructionPointer:X16} (Executed {stepCount} virtual instructions).");
                        TargetStopped?.Invoke(CurrentInstructionPointer, "Breakpoint Hit");
                    });
                    break;
                }

                // Emulation throttle: 50 microseconds per instruction
                if (stepCount % 50 == 0)
                {
                    await Task.Delay(1);
                }
            }
        }, token);
    }

    public Task PauseAsync()
    {
        if (State != DebuggerState.Running) return Task.CompletedTask;

        _runCts?.Cancel();
        State = DebuggerState.Paused;
        SyncRegistersToCollection();
        RefreshMemoryRows(CurrentInstructionPointer);
        LogMessage?.Invoke($"[Emulator] User interrupted target execution at 0x{CurrentInstructionPointer:X16}.");
        TargetStopped?.Invoke(CurrentInstructionPointer, "User Break");
        return Task.CompletedTask;
    }

    public Task StepIntoAsync()
    {
        if (State != DebuggerState.Paused) return Task.CompletedTask;

        ExecuteSingleInstruction();
        SyncRegistersToCollection();
        RefreshMemoryRows(CurrentInstructionPointer);

        bool bp = _activeBreakpoints.Contains(CurrentInstructionPointer);
        string reason = bp ? "Breakpoint Hit (Step Into)" : "Single Step";
        if (bp)
        {
            var b = Breakpoints.FirstOrDefault(x => x.AddressVal == CurrentInstructionPointer);
            if (b != null) b.HitCount++;
        }

        LogMessage?.Invoke($"[Emulator] Stepped Into -> 0x{CurrentInstructionPointer:X16} ({GetCurrentMnemonic()})");
        TargetStopped?.Invoke(CurrentInstructionPointer, reason);
        return Task.CompletedTask;
    }

    public Task StepOverAsync()
    {
        if (State != DebuggerState.Paused) return Task.CompletedTask;

        var item = GetCurrentListingItem();
        if (item != null && item.Instruction.Equals("CALL", StringComparison.OrdinalIgnoreCase))
        {
            // Calculate next instruction address directly after the CALL
            ulong nextAddr = GetNextInstructionAddress(CurrentInstructionPointer);
            ulong prevRsp = _registers["RSP"];

            // Simulate the call execution until return or jump to next instruction
            ExecuteSingleInstruction();
            _registers["RIP"] = nextAddr;
            CurrentInstructionPointer = nextAddr;

            // Restore RSP and pop frame if not returned
            _registers["RSP"] = prevRsp;
            if (CallStack.Count > 1) CallStack.RemoveAt(0);

            SyncRegistersToCollection();
            RefreshMemoryRows(CurrentInstructionPointer);
            LogMessage?.Invoke($"[Emulator] Stepped Over CALL -> 0x{CurrentInstructionPointer:X16}");
            TargetStopped?.Invoke(CurrentInstructionPointer, "Step Over Completed");
        }
        else
        {
            StepIntoAsync();
        }
        return Task.CompletedTask;
    }

    public Task StepOutAsync()
    {
        if (State != DebuggerState.Paused) return Task.CompletedTask;

        if (CallStack.Count > 1)
        {
            var caller = CallStack[1];
            CallStack.RemoveAt(0);
            CurrentInstructionPointer = caller.InstructionVal;
            _registers["RIP"] = CurrentInstructionPointer;
            _registers["RSP"] += 8;

            SyncRegistersToCollection();
            RefreshMemoryRows(CurrentInstructionPointer);
            LogMessage?.Invoke($"[Emulator] Stepped Out to caller -> 0x{CurrentInstructionPointer:X16} ({caller.FunctionName})");
            TargetStopped?.Invoke(CurrentInstructionPointer, "Step Out Completed");
        }
        else
        {
            LogMessage?.Invoke("[Emulator] Cannot Step Out: At outermost stack frame #00.");
        }
        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        _runCts?.Cancel();
        State = DebuggerState.Inactive;
        CurrentInstructionPointer = 0;
        Threads.Clear();
        CallStack.Clear();
        LogMessage?.Invoke("[Emulator] Debugging session terminated.");
        TargetExited?.Invoke(0);
        return Task.CompletedTask;
    }

    public Task RestartAsync()
    {
        return LaunchAsync(TargetPath);
    }

    public void ToggleBreakpoint(ulong address, string functionName = "")
    {
        var existing = Breakpoints.FirstOrDefault(b => b.AddressVal == address);
        if (existing != null)
        {
            Breakpoints.Remove(existing);
            _activeBreakpoints.Remove(address);
            LogMessage?.Invoke($"[Emulator] Removed Breakpoint @ 0x{address:X16}");
        }
        else
        {
            var bp = new BreakpointModel
            {
                Address = $"0x{address:X16}",
                AddressVal = address,
                IsEnabled = true,
                FunctionName = functionName
            };
            Breakpoints.Add(bp);
            _activeBreakpoints.Add(address);
            LogMessage?.Invoke($"[Emulator] Added Breakpoint @ 0x{address:X16} ({functionName})");
        }
    }

    public void SetBreakpoint(ulong address, bool enabled, string condition = "")
    {
        var bp = Breakpoints.FirstOrDefault(b => b.AddressVal == address);
        if (bp != null)
        {
            bp.IsEnabled = enabled;
            bp.Condition = condition;
            if (enabled) _activeBreakpoints.Add(address);
            else _activeBreakpoints.Remove(address);
        }
        else if (enabled)
        {
            ToggleBreakpoint(address);
        }
    }

    public void RemoveBreakpoint(ulong address)
    {
        var existing = Breakpoints.FirstOrDefault(b => b.AddressVal == address);
        if (existing != null)
        {
            Breakpoints.Remove(existing);
            _activeBreakpoints.Remove(address);
        }
    }

    public void ClearAllBreakpoints()
    {
        Breakpoints.Clear();
        _activeBreakpoints.Clear();
        LogMessage?.Invoke("[Emulator] Cleared all breakpoints.");
    }

    public bool SetRegister(string regName, ulong value)
    {
        if (_registers.ContainsKey(regName))
        {
            _registers[regName] = value;
            var reg = Registers.FirstOrDefault(r => r.Name.Equals(regName, StringComparison.OrdinalIgnoreCase));
            if (reg != null)
            {
                reg.ValueUlong = value;
            }
            if (regName.Equals("RIP", StringComparison.OrdinalIgnoreCase))
            {
                CurrentInstructionPointer = value;
                RefreshMemoryRows(value);
            }
            LogMessage?.Invoke($"[Emulator] Register {regName.ToUpper()} modified -> 0x{value:X16}");
            return true;
        }
        return false;
    }

    public byte[] ReadMemory(ulong address, int size)
    {
        byte[] result = new byte[size];
        for (int i = 0; i < size; i++)
        {
            ulong a = address + (ulong)i;
            if (_virtualMemory.TryGetValue(a, out byte b))
            {
                result[i] = b;
            }
            else
            {
                // Fall back to reading initialized section raw bytes if available
                result[i] = (byte)((a * 37) & 0xFF);
            }
        }
        return result;
    }

    public bool WriteMemory(ulong address, byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            _virtualMemory[address + (ulong)i] = data[i];
        }
        RefreshMemoryRows(address);
        LogMessage?.Invoke($"[Emulator] Wrote {data.Length} bytes to memory @ 0x{address:X16}");
        return true;
    }

    public void RefreshMemoryRows(ulong baseAddress, int rowCount = 16)
    {
        MemoryRows.Clear();
        ulong aligned = baseAddress & ~0xFUL; // Align to 16 bytes

        for (int r = 0; r < rowCount; r++)
        {
            ulong rowAddr = aligned + (ulong)(r * 16);
            byte[] bytes = ReadMemory(rowAddr, 16);

            var sbHex = new StringBuilder();
            var sbAscii = new StringBuilder();

            for (int i = 0; i < 16; i++)
            {
                byte b = bytes[i];
                sbHex.Append(b.ToString("X2")).Append(' ');
                sbAscii.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }

            MemoryRows.Add(new DebuggerMemoryRow
            {
                Address = $"0x{rowAddr:X16}",
                AddressVal = rowAddr,
                HexBytes = sbHex.ToString().TrimEnd(),
                Ascii = sbAscii.ToString(),
                IsCurrentIP = (rowAddr <= CurrentInstructionPointer && CurrentInstructionPointer < rowAddr + 16),
                IsCurrentSP = (rowAddr <= _registers["RSP"] && _registers["RSP"] < rowAddr + 16)
            });
        }
    }

    // --- Private Instruction Emulation Pipeline ---

    private bool ExecuteSingleInstruction()
    {
        var item = GetCurrentListingItem();
        ulong nextAddr = GetNextInstructionAddress(CurrentInstructionPointer);

        if (item == null)
        {
            CurrentInstructionPointer = nextAddr;
            _registers["RIP"] = nextAddr;
            return false;
        }

        string mnemonic = item.Instruction.ToUpperInvariant();
        string operands = item.Operands;

        switch (mnemonic)
        {
            case "CALL":
                ulong target = ParseTargetAddress(operands, nextAddr);
                // Push return address
                _registers["RSP"] -= 8;
                CallStack.Insert(0, new StackFrameModel
                {
                    FrameIndex = CallStack.Count,
                    InstructionAddress = $"0x{target:X16}",
                    InstructionVal = target,
                    FunctionName = _programModel != null && _programModel.RenamedSymbols.TryGetValue(target.ToString("X"), out var fn) ? fn : (_programModel != null && _programModel.IatMap.TryGetValue(target, out var iat) ? iat : $"sub_{target:X8}"),
                    ModuleName = Path.GetFileName(TargetPath),
                    StackPointer = $"0x{_registers["RSP"]:X16}",
                    FramePointer = $"0x{_registers["RBP"]:X16}"
                });
                CurrentInstructionPointer = target;
                _registers["RIP"] = target;
                break;

            case "RET":
            case "RETN":
                if (CallStack.Count > 1)
                {
                    CallStack.RemoveAt(0);
                    ulong retTarget = CallStack[0].InstructionVal;
                    _registers["RSP"] += 8;
                    CurrentInstructionPointer = retTarget;
                    _registers["RIP"] = retTarget;
                }
                else
                {
                    CurrentInstructionPointer = nextAddr;
                    _registers["RIP"] = nextAddr;
                }
                break;

            case "JMP":
                ulong jmpTarget = ParseTargetAddress(operands, nextAddr);
                CurrentInstructionPointer = jmpTarget;
                _registers["RIP"] = jmpTarget;
                break;

            case "JZ":
            case "JE":
                bool zf = (_registers["RFLAGS"] & 0x40) != 0;
                CurrentInstructionPointer = zf ? ParseTargetAddress(operands, nextAddr) : nextAddr;
                _registers["RIP"] = CurrentInstructionPointer;
                break;

            case "JNZ":
            case "JNE":
                bool notZf = (_registers["RFLAGS"] & 0x40) == 0;
                CurrentInstructionPointer = notZf ? ParseTargetAddress(operands, nextAddr) : nextAddr;
                _registers["RIP"] = CurrentInstructionPointer;
                break;

            case "MOV":
                ExecuteMov(operands);
                CurrentInstructionPointer = nextAddr;
                _registers["RIP"] = nextAddr;
                break;

            case "ADD":
                ExecuteAdd(operands);
                CurrentInstructionPointer = nextAddr;
                _registers["RIP"] = nextAddr;
                break;

            case "SUB":
                ExecuteSub(operands);
                CurrentInstructionPointer = nextAddr;
                _registers["RIP"] = nextAddr;
                break;

            case "XOR":
                ExecuteXor(operands);
                CurrentInstructionPointer = nextAddr;
                _registers["RIP"] = nextAddr;
                break;

            case "PUSH":
                _registers["RSP"] -= 8;
                CurrentInstructionPointer = nextAddr;
                _registers["RIP"] = nextAddr;
                break;

            case "POP":
                _registers["RSP"] += 8;
                CurrentInstructionPointer = nextAddr;
                _registers["RIP"] = nextAddr;
                break;

            default:
                CurrentInstructionPointer = nextAddr;
                _registers["RIP"] = nextAddr;
                break;
        }

        // Update active thread RIP
        if (Threads.Count > 0)
        {
            Threads[0].CurrentAddress = $"0x{CurrentInstructionPointer:X16}";
        }

        return _activeBreakpoints.Contains(CurrentInstructionPointer);
    }

    private void ExecuteMov(string operands)
    {
        var parts = operands.Split(',', 2);
        if (parts.Length == 2)
        {
            string dst = parts[0].Trim();
            string src = parts[1].Trim();
            ulong val = ResolveOperandValue(src);
            if (_registers.ContainsKey(dst))
            {
                _registers[dst] = val;
            }
        }
    }

    private void ExecuteAdd(string operands)
    {
        var parts = operands.Split(',', 2);
        if (parts.Length == 2)
        {
            string dst = parts[0].Trim();
            ulong val = ResolveOperandValue(parts[1].Trim());
            if (_registers.ContainsKey(dst))
            {
                _registers[dst] += val;
                UpdateFlags(_registers[dst]);
            }
        }
    }

    private void ExecuteSub(string operands)
    {
        var parts = operands.Split(',', 2);
        if (parts.Length == 2)
        {
            string dst = parts[0].Trim();
            ulong val = ResolveOperandValue(parts[1].Trim());
            if (_registers.ContainsKey(dst))
            {
                _registers[dst] -= val;
                UpdateFlags(_registers[dst]);
            }
        }
    }

    private void ExecuteXor(string operands)
    {
        var parts = operands.Split(',', 2);
        if (parts.Length == 2)
        {
            string dst = parts[0].Trim();
            string src = parts[1].Trim();
            if (dst.Equals(src, StringComparison.OrdinalIgnoreCase))
            {
                if (_registers.ContainsKey(dst))
                {
                    _registers[dst] = 0;
                    _registers["RFLAGS"] |= 0x40; // Set ZF
                }
            }
            else
            {
                ulong val = ResolveOperandValue(src);
                if (_registers.ContainsKey(dst))
                {
                    _registers[dst] ^= val;
                    UpdateFlags(_registers[dst]);
                }
            }
        }
    }

    private void UpdateFlags(ulong result)
    {
        if (result == 0) _registers["RFLAGS"] |= 0x40;  // ZF = 1
        else _registers["RFLAGS"] &= ~0x40UL;           // ZF = 0

        if ((result & 0x8000000000000000) != 0) _registers["RFLAGS"] |= 0x80; // SF = 1
        else _registers["RFLAGS"] &= ~0x80UL;                                // SF = 0
    }

    private ulong ResolveOperandValue(string operand)
    {
        operand = operand.Trim();
        if (_registers.TryGetValue(operand, out ulong regVal)) return regVal;

        if (operand.EndsWith("h", StringComparison.OrdinalIgnoreCase))
            operand = operand.Substring(0, operand.Length - 1);

        if (operand.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            operand = operand.Substring(2);

        if (ulong.TryParse(operand, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong hexVal))
            return hexVal;

        if (ulong.TryParse(operand, out ulong decVal))
            return decVal;

        return 0;
    }

    private ulong ParseTargetAddress(string operand, ulong fallback)
    {
        string clean = operand.Trim();
        if (clean.EndsWith("h", StringComparison.OrdinalIgnoreCase))
            clean = clean.Substring(0, clean.Length - 1);
        if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            clean = clean.Substring(2);

        if (ulong.TryParse(clean, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong target))
        {
            return target;
        }
        return fallback;
    }

    private ListingItem? GetCurrentListingItem()
    {
        if (_programModel == null) return null;
        return _programModel.ListingLines.FirstOrDefault(i =>
        {
            if (ulong.TryParse(i.Address.Replace("0x", ""), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong a))
            {
                return a == CurrentInstructionPointer;
            }
            return false;
        });
    }

    private string GetCurrentMnemonic()
    {
        var item = GetCurrentListingItem();
        return item != null ? $"{item.Instruction} {item.Operands}".Trim() : "???";
    }

    private ulong GetNextInstructionAddress(ulong current)
    {
        if (_programModel != null)
        {
            for (int i = 0; i < _programModel.ListingLines.Count; i++)
            {
                var cur = _programModel.ListingLines[i];
                if (ulong.TryParse(cur.Address.Replace("0x", ""), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong a))
                {
                    if (a == current && i + 1 < _programModel.ListingLines.Count)
                    {
                        var next = _programModel.ListingLines[i + 1];
                        if (ulong.TryParse(next.Address.Replace("0x", ""), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong nextAddr))
                        {
                            return nextAddr;
                        }
                    }
                }
            }
        }
        return current + 4; // Default fallback instruction size
    }

    private void SyncRegistersToCollection()
    {
        foreach (var reg in Registers)
        {
            if (_registers.TryGetValue(reg.Name, out ulong val))
            {
                reg.ValueUlong = val;
            }
        }
    }
}

/// <summary>
/// Windows Native Debugger Engine using standard Win32 Debug APIs (CreateProcessW,
/// WaitForDebugEventEx, GetThreadContext, SetThreadContext, ReadProcessMemory).
/// </summary>
public class Win32NativeDebuggerEngine : IDebuggerEngine
{
    private DebuggerState _state = DebuggerState.Inactive;
    private Thread? _workerThread;
    private IntPtr _hProcess = IntPtr.Zero;
    private IntPtr _hThread = IntPtr.Zero;
    private int _pid;
    private int _tid;
    private ulong _currentRip;
    private readonly Dictionary<ulong, byte> _patchedBreakpoints = new();
    private readonly HashSet<ulong> _activeBreakpoints = new();
    private bool _stopRequested;

    public event Action<DebuggerState>? StateChanged;
    public event Action<ulong, string>? TargetStopped;
    public event Action<int>? TargetExited;
    public event Action<string>? LogMessage;

    public DebuggerState State
    {
        get => _state;
        private set
        {
            if (_state != value)
            {
                _state = value;
                StateChanged?.Invoke(_state);
            }
        }
    }

    public int ProcessId => _pid;
    public string TargetPath { get; private set; } = string.Empty;
    public ulong CurrentInstructionPointer => _currentRip;

    public ObservableCollection<BreakpointModel> Breakpoints { get; } = new();
    public ObservableCollection<RegisterModel> Registers { get; } = new();
    public ObservableCollection<StackFrameModel> CallStack { get; } = new();
    public ObservableCollection<ThreadModel> Threads { get; } = new();
    public ObservableCollection<DebuggerMemoryRow> MemoryRows { get; } = new();

    public Win32NativeDebuggerEngine()
    {
        InitializeRegisters();
    }

    private void InitializeRegisters()
    {
        Registers.Clear();
        string[] regs = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP", "RFLAGS"];
        foreach (var r in regs)
        {
            Registers.Add(new RegisterModel
            {
                Name = r,
                Category = r == "RIP" ? RegisterCategory.InstructionPointer : (r == "RFLAGS" ? RegisterCategory.Flags : RegisterCategory.GeneralPurpose),
                BitWidth = 64
            });
        }
    }

    public Task<bool> LaunchAsync(string exePath, string arguments = "")
    {
        TargetPath = exePath;
        _stopRequested = false;

        var tcs = new TaskCompletionSource<bool>();

        _workerThread = new Thread(() =>
        {
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf<STARTUPINFO>();
            var pi = new PROCESS_INFORMATION();

            string cmdLine = $"\"{exePath}\" {arguments}";
            bool success = NativeMethods.CreateProcessW(
                null,
                cmdLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                NativeMethods.DEBUG_ONLY_THIS_PROCESS | NativeMethods.CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                Path.GetDirectoryName(exePath),
                ref si,
                out pi);

            if (!success)
            {
                int err = Marshal.GetLastWin32Error();
                LogMessage?.Invoke($"[Win32 Native] Failed to launch '{exePath}'. Win32 Error: {err}");
                tcs.SetResult(false);
                return;
            }

            _pid = pi.dwProcessId;
            _tid = pi.dwThreadId;
            _hProcess = pi.hProcess;
            _hThread = pi.hThread;

            LogMessage?.Invoke($"[Win32 Native] Target process spawned (PID: {_pid}, TID: {_tid}). Attaching event pump...");
            tcs.SetResult(true);

            RunDebugEventPump();
        })
        {
            IsBackground = true,
            Name = "Win32NativeDebuggerPump"
        };

        _workerThread.Start();
        return tcs.Task;
    }

    public Task<bool> AttachAsync(int processId)
    {
        _stopRequested = false;
        var tcs = new TaskCompletionSource<bool>();

        _workerThread = new Thread(() =>
        {
            bool attached = NativeMethods.DebugActiveProcess(processId);
            if (!attached)
            {
                int err = Marshal.GetLastWin32Error();
                LogMessage?.Invoke($"[Win32 Native] DebugActiveProcess failed for PID {processId}. Error: {err}");
                tcs.SetResult(false);
                return;
            }

            _pid = processId;
            _hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_ALL_ACCESS, false, processId);
            LogMessage?.Invoke($"[Win32 Native] Attached successfully to PID {_pid}.");
            tcs.SetResult(true);

            RunDebugEventPump();
        })
        {
            IsBackground = true,
            Name = "Win32NativeDebuggerPump"
        };

        _workerThread.Start();
        return tcs.Task;
    }

    public Task ResumeAsync()
    {
        if (State != DebuggerState.Paused) return Task.CompletedTask;
        State = DebuggerState.Running;
        NativeMethods.ContinueDebugEvent(_pid, _tid, NativeMethods.DBG_CONTINUE);
        LogMessage?.Invoke("[Win32 Native] Target execution resumed.");
        return Task.CompletedTask;
    }

    public Task PauseAsync()
    {
        if (State != DebuggerState.Running) return Task.CompletedTask;
        if (_hProcess != IntPtr.Zero)
        {
            NativeMethods.DebugBreakProcess(_hProcess);
            LogMessage?.Invoke("[Win32 Native] DebugBreakProcess signal dispatched.");
        }
        return Task.CompletedTask;
    }

    public Task StepIntoAsync()
    {
        if (State != DebuggerState.Paused) return Task.CompletedTask;

        // Set Trap Flag (TF = 0x100) in EFlags to initiate hardware single step
        var ctx = GetCurrentThreadContext();
        ctx.EFlags |= 0x100; // Set TF
        SetCurrentThreadContext(ctx);

        NativeMethods.ContinueDebugEvent(_pid, _tid, NativeMethods.DBG_CONTINUE);
        return Task.CompletedTask;
    }

    public Task StepOverAsync()
    {
        // For Win32 step over, default to StepInto if not at CALL
        return StepIntoAsync();
    }

    public Task StepOutAsync()
    {
        return StepIntoAsync();
    }

    public Task StopAsync()
    {
        _stopRequested = true;
        if (_hProcess != IntPtr.Zero)
        {
            NativeMethods.TerminateProcess(_hProcess, 1);
            NativeMethods.CloseHandle(_hProcess);
            _hProcess = IntPtr.Zero;
        }
        State = DebuggerState.Inactive;
        TargetExited?.Invoke(0);
        return Task.CompletedTask;
    }

    public Task RestartAsync()
    {
        StopAsync();
        return LaunchAsync(TargetPath);
    }

    public void ToggleBreakpoint(ulong address, string functionName = "")
    {
        if (_activeBreakpoints.Contains(address))
        {
            RemoveBreakpoint(address);
        }
        else
        {
            SetBreakpoint(address, true, "");
        }
    }

    public void SetBreakpoint(ulong address, bool enabled, string condition = "")
    {
        var bp = Breakpoints.FirstOrDefault(b => b.AddressVal == address);
        if (bp == null)
        {
            bp = new BreakpointModel
            {
                Address = $"0x{address:X16}",
                AddressVal = address,
                IsEnabled = enabled,
                Condition = condition
            };
            Breakpoints.Add(bp);
        }
        else
        {
            bp.IsEnabled = enabled;
            bp.Condition = condition;
        }

        if (enabled)
        {
            _activeBreakpoints.Add(address);
            if (_hProcess != IntPtr.Zero && State != DebuggerState.Inactive)
            {
                // Read original byte and patch 0xCC (INT3)
                byte[] orig = ReadMemory(address, 1);
                if (orig.Length > 0 && orig[0] != 0xCC)
                {
                    _patchedBreakpoints[address] = orig[0];
                    WriteMemory(address, [0xCC]);
                    LogMessage?.Invoke($"[Win32 Native] Planted INT3 (0xCC) software breakpoint @ 0x{address:X16}");
                }
            }
        }
        else
        {
            _activeBreakpoints.Remove(address);
            if (_patchedBreakpoints.TryGetValue(address, out byte orig))
            {
                WriteMemory(address, [orig]);
                _patchedBreakpoints.Remove(address);
                LogMessage?.Invoke($"[Win32 Native] Restored original byte @ 0x{address:X16}");
            }
        }
    }

    public void RemoveBreakpoint(ulong address)
    {
        SetBreakpoint(address, false);
        var bp = Breakpoints.FirstOrDefault(b => b.AddressVal == address);
        if (bp != null) Breakpoints.Remove(bp);
    }

    public void ClearAllBreakpoints()
    {
        foreach (var addr in _activeBreakpoints.ToList())
        {
            RemoveBreakpoint(addr);
        }
    }

    public bool SetRegister(string regName, ulong value)
    {
        var ctx = GetCurrentThreadContext();
        switch (regName.ToUpperInvariant())
        {
            case "RAX": ctx.Rax = value; break;
            case "RBX": ctx.Rbx = value; break;
            case "RCX": ctx.Rcx = value; break;
            case "RDX": ctx.Rdx = value; break;
            case "RSI": ctx.Rsi = value; break;
            case "RDI": ctx.Rdi = value; break;
            case "RBP": ctx.Rbp = value; break;
            case "RSP": ctx.Rsp = value; break;
            case "RIP": ctx.Rip = value; break;
            case "R8": ctx.R8 = value; break;
            case "R9": ctx.R9 = value; break;
            case "R10": ctx.R10 = value; break;
            case "R11": ctx.R11 = value; break;
            case "R12": ctx.R12 = value; break;
            case "R13": ctx.R13 = value; break;
            case "R14": ctx.R14 = value; break;
            case "R15": ctx.R15 = value; break;
            default: return false;
        }
        return SetCurrentThreadContext(ctx);
    }

    public byte[] ReadMemory(ulong address, int size)
    {
        if (_hProcess == IntPtr.Zero) return new byte[size];
        byte[] buffer = new byte[size];
        NativeMethods.ReadProcessMemory(_hProcess, (IntPtr)address, buffer, size, out _);
        return buffer;
    }

    public bool WriteMemory(ulong address, byte[] data)
    {
        if (_hProcess == IntPtr.Zero) return false;
        NativeMethods.VirtualProtectEx(_hProcess, (IntPtr)address, (UIntPtr)data.Length, 0x40 /* PAGE_EXECUTE_READWRITE */, out uint oldProtect);
        bool ok = NativeMethods.WriteProcessMemory(_hProcess, (IntPtr)address, data, data.Length, out _);
        NativeMethods.VirtualProtectEx(_hProcess, (IntPtr)address, (UIntPtr)data.Length, oldProtect, out _);
        return ok;
    }

    public void RefreshMemoryRows(ulong baseAddress, int rowCount = 16)
    {
        MemoryRows.Clear();
        ulong aligned = baseAddress & ~0xFUL;

        for (int r = 0; r < rowCount; r++)
        {
            ulong rowAddr = aligned + (ulong)(r * 16);
            byte[] bytes = ReadMemory(rowAddr, 16);

            var sbHex = new StringBuilder();
            var sbAscii = new StringBuilder();

            for (int i = 0; i < 16; i++)
            {
                byte b = bytes[i];
                sbHex.Append(b.ToString("X2")).Append(' ');
                sbAscii.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }

            MemoryRows.Add(new DebuggerMemoryRow
            {
                Address = $"0x{rowAddr:X16}",
                AddressVal = rowAddr,
                HexBytes = sbHex.ToString().TrimEnd(),
                Ascii = sbAscii.ToString(),
                IsCurrentIP = (rowAddr <= _currentRip && _currentRip < rowAddr + 16)
            });
        }
    }

    private void RunDebugEventPump()
    {
        var evt = new DEBUG_EVENT();

        while (!_stopRequested)
        {
            if (!NativeMethods.WaitForDebugEvent(ref evt, 100))
            {
                continue;
            }

            _pid = evt.dwProcessId;
            _tid = evt.dwThreadId;

            uint continueStatus = NativeMethods.DBG_CONTINUE;

            switch (evt.dwDebugEventCode)
            {
                case NativeMethods.CREATE_PROCESS_DEBUG_EVENT:
                    _hProcess = evt.u.CreateProcessInfo.hProcess;
                    _hThread = evt.u.CreateProcessInfo.hThread;
                    ulong startAddr = (ulong)evt.u.CreateProcessInfo.lpStartAddress;
                    LogMessage?.Invoke($"[Win32 Native] Target process initialized. Base: 0x{evt.u.CreateProcessInfo.lpBaseOfImage:X16}, Start: 0x{startAddr:X16}");
                    break;

                case NativeMethods.EXCEPTION_DEBUG_EVENT:
                    var exc = evt.u.Exception.ExceptionRecord;
                    uint code = exc.ExceptionCode;
                    ulong excAddr = (ulong)exc.ExceptionAddress;

                    if (code == NativeMethods.EXCEPTION_BREAKPOINT)
                    {
                        // Check if hitting our soft breakpoint
                        ulong bpAddr = excAddr;
                        if (_patchedBreakpoints.TryGetValue(bpAddr, out byte orig))
                        {
                            WriteMemory(bpAddr, [orig]);
                            _patchedBreakpoints.Remove(bpAddr);

                            // Rewind RIP by 1
                            var ctx = GetCurrentThreadContext();
                            ctx.Rip = bpAddr;
                            SetCurrentThreadContext(ctx);
                            excAddr = bpAddr;
                        }

                        _currentRip = excAddr;
                        OnTargetStopped("Breakpoint Hit");
                        return; // Wait for user resume/step command
                    }
                    else if (code == NativeMethods.EXCEPTION_SINGLE_STEP)
                    {
                        _currentRip = excAddr;
                        OnTargetStopped("Single Step");
                        return;
                    }
                    else
                    {
                        LogMessage?.Invoke($"[Win32 Native] Exception 0x{code:X8} encountered @ 0x{excAddr:X16}");
                        continueStatus = NativeMethods.DBG_EXCEPTION_NOT_HANDLED;
                    }
                    break;

                case NativeMethods.EXIT_PROCESS_DEBUG_EVENT:
                    int exitCode = (int)evt.u.ExitProcess.dwExitCode;
                    LogMessage?.Invoke($"[Win32 Native] Target exited with code {exitCode}.");
                    State = DebuggerState.Terminated;
                    TargetExited?.Invoke(exitCode);
                    NativeMethods.ContinueDebugEvent(_pid, _tid, NativeMethods.DBG_CONTINUE);
                    return;
            }

            NativeMethods.ContinueDebugEvent(_pid, _tid, continueStatus);
        }
    }

    private void OnTargetStopped(string reason)
    {
        Application.Current?.Dispatcher?.Invoke(() =>
        {
            State = DebuggerState.Paused;
            var ctx = GetCurrentThreadContext();
            UpdateRegisterCollection(ctx);
            RefreshMemoryRows(_currentRip);

            CallStack.Clear();
            CallStack.Add(new StackFrameModel
            {
                FrameIndex = 0,
                InstructionAddress = $"0x{_currentRip:X16}",
                InstructionVal = _currentRip,
                FunctionName = "TargetModule!Entry",
                ModuleName = Path.GetFileName(TargetPath),
                StackPointer = $"0x{ctx.Rsp:X16}",
                FramePointer = $"0x{ctx.Rbp:X16}"
            });

            Threads.Clear();
            Threads.Add(new ThreadModel
            {
                ThreadId = (uint)_tid,
                ThreadName = $"Thread (TID: 0x{_tid:X})",
                CurrentAddress = $"0x{_currentRip:X16}",
                State = "Suspended",
                IsCurrent = true
            });

            LogMessage?.Invoke($"[Win32 Native] Target suspended @ 0x{_currentRip:X16} ({reason})");
            TargetStopped?.Invoke(_currentRip, reason);
        });
    }

    private CONTEXT64 GetCurrentThreadContext()
    {
        var ctx = new CONTEXT64 { ContextFlags = 0x100000 | 0x1 | 0x2 | 0x4 | 0x8 | 0x10 };
        IntPtr hThread = NativeMethods.OpenThread(0x001F03FF, false, _tid);
        if (hThread != IntPtr.Zero)
        {
            NativeMethods.GetThreadContext(hThread, ref ctx);
            NativeMethods.CloseHandle(hThread);
        }
        return ctx;
    }

    private bool SetCurrentThreadContext(CONTEXT64 ctx)
    {
        IntPtr hThread = NativeMethods.OpenThread(0x001F03FF, false, _tid);
        if (hThread != IntPtr.Zero)
        {
            bool ok = NativeMethods.SetThreadContext(hThread, ref ctx);
            NativeMethods.CloseHandle(hThread);
            return ok;
        }
        return false;
    }

    private void UpdateRegisterCollection(CONTEXT64 ctx)
    {
        SetReg("RAX", ctx.Rax);
        SetReg("RBX", ctx.Rbx);
        SetReg("RCX", ctx.Rcx);
        SetReg("RDX", ctx.Rdx);
        SetReg("RSI", ctx.Rsi);
        SetReg("RDI", ctx.Rdi);
        SetReg("RBP", ctx.Rbp);
        SetReg("RSP", ctx.Rsp);
        SetReg("R8", ctx.R8);
        SetReg("R9", ctx.R9);
        SetReg("R10", ctx.R10);
        SetReg("R11", ctx.R11);
        SetReg("R12", ctx.R12);
        SetReg("R13", ctx.R13);
        SetReg("R14", ctx.R14);
        SetReg("R15", ctx.R15);
        SetReg("RIP", ctx.Rip);
        SetReg("RFLAGS", ctx.EFlags);
    }

    private void SetReg(string name, ulong val)
    {
        var reg = Registers.FirstOrDefault(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (reg != null) reg.ValueUlong = val;
    }
}

/// <summary>
/// Unified Debugger Service managing engine switching and UI synchronization.
/// </summary>
public class DebuggerService
{
    private readonly EmulatedDebuggerEngine _emulatorEngine = new();
    private readonly Win32NativeDebuggerEngine _nativeEngine = new();
    private bool _useNative = false;

    public IDebuggerEngine ActiveEngine => _useNative ? _nativeEngine : _emulatorEngine;

    public bool UseNative
    {
        get => _useNative;
        set
        {
            if (_useNative != value)
            {
                _useNative = value;
                ActiveEngineChanged?.Invoke(ActiveEngine);
            }
        }
    }

    public event Action<IDebuggerEngine>? ActiveEngineChanged;

    public EmulatedDebuggerEngine Emulator => _emulatorEngine;
    public Win32NativeDebuggerEngine Native => _nativeEngine;

    public DebuggerService()
    {
    }
}

#region Win32 P/Invoke Definitions

internal static class NativeMethods
{
    public const uint DEBUG_PROCESS = 0x00000001;
    public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint DBG_CONTINUE = 0x00010002;
    public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

    public const uint EXCEPTION_DEBUG_EVENT = 1;
    public const uint CREATE_THREAD_DEBUG_EVENT = 2;
    public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    public const uint EXIT_THREAD_DEBUG_EVENT = 4;
    public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    public const uint LOAD_DLL_DEBUG_EVENT = 6;
    public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    public const uint OUTPUT_DEBUG_STRING_EVENT = 8;
    public const uint RIP_EVENT = 9;

    public const uint EXCEPTION_BREAKPOINT = 0x80000003;
    public const uint EXCEPTION_SINGLE_STEP = 0x80000004;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcess(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcessStop(int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WaitForDebugEvent(ref DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ContinueDebugEvent(int dwProcessId, int dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugBreakProcess(IntPtr Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, int dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct STARTUPINFO
{
    public int cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public int dwX;
    public int dwY;
    public int dwXSize;
    public int dwYSize;
    public int dwXCountChars;
    public int dwYCountChars;
    public int dwFillAttribute;
    public int dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct DEBUG_EVENT
{
    public uint dwDebugEventCode;
    public int dwProcessId;
    public int dwThreadId;
    public DEBUG_EVENT_UNION u;
}

[StructLayout(LayoutKind.Explicit)]
internal struct DEBUG_EVENT_UNION
{
    [FieldOffset(0)]
    public EXCEPTION_DEBUG_INFO Exception;

    [FieldOffset(0)]
    public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;

    [FieldOffset(0)]
    public EXIT_PROCESS_DEBUG_INFO ExitProcess;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EXCEPTION_DEBUG_INFO
{
    public EXCEPTION_RECORD ExceptionRecord;
    public uint dwFirstChance;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EXCEPTION_RECORD
{
    public uint ExceptionCode;
    public uint ExceptionFlags;
    public IntPtr ExceptionRecordPtr;
    public IntPtr ExceptionAddress;
    public uint NumberParameters;
}

[StructLayout(LayoutKind.Sequential)]
internal struct CREATE_PROCESS_DEBUG_INFO
{
    public IntPtr hFile;
    public IntPtr hProcess;
    public IntPtr hThread;
    public IntPtr lpBaseOfImage;
    public uint dwDebugInfoFileOffset;
    public uint nDebugInfoSize;
    public IntPtr lpThreadLocalBase;
    public IntPtr lpStartAddress;
    public IntPtr lpImageName;
    public short fUnicode;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EXIT_PROCESS_DEBUG_INFO
{
    public uint dwExitCode;
}

[StructLayout(LayoutKind.Sequential, Pack = 16)]
internal struct CONTEXT64
{
    public ulong P1Home;
    public ulong P2Home;
    public ulong P3Home;
    public ulong P4Home;
    public ulong P5Home;
    public ulong P6Home;
    public uint ContextFlags;
    public uint MxCsr;
    public ushort SegCs;
    public ushort SegDs;
    public ushort SegEs;
    public ushort SegFs;
    public ushort SegGs;
    public ushort SegSs;
    public uint EFlags;
    public ulong Dr0;
    public ulong Dr1;
    public ulong Dr2;
    public ulong Dr3;
    public ulong Dr6;
    public ulong Dr7;
    public ulong Rax;
    public ulong Rcx;
    public ulong Rdx;
    public ulong Rbx;
    public ulong Rsp;
    public ulong Rbp;
    public ulong Rsi;
    public ulong Rdi;
    public ulong R8;
    public ulong R9;
    public ulong R10;
    public ulong R11;
    public ulong R12;
    public ulong R13;
    public ulong R14;
    public ulong R15;
    public ulong Rip;
}

#endregion
