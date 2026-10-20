using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Ghidra.UI.Models;

/// <summary>
/// Operational state of the debugger engine.
/// </summary>
public enum DebuggerState
{
    Inactive,
    Running,
    Paused,
    Terminated
}

/// <summary>
/// Classification of debugger breakpoints.
/// </summary>
public enum BreakpointType
{
    Software,          // INT 3 (0xCC)
    HardwareExecute,   // DR0-DR3
    HardwareWrite,     // Watchpoint
    HardwareReadWrite  // Access watchpoint
}

/// <summary>
/// Represents a breakpoint in target memory.
/// </summary>
public class BreakpointModel : INotifyPropertyChanged
{
    private bool _isEnabled = true;
    private int _hitCount;
    private string _condition = string.Empty;

    public string Address { get; set; } = string.Empty;
    public ulong AddressVal { get; set; }
    public BreakpointType Type { get; set; } = BreakpointType.Software;
    public string FunctionName { get; set; } = string.Empty;
    public byte OriginalByte { get; set; } = 0x90;

    public bool IsEnabled
    {
        get => _isEnabled;
        set
        {
            if (_isEnabled != value)
            {
                _isEnabled = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusText));
            }
        }
    }

    public int HitCount
    {
        get => _hitCount;
        set
        {
            if (_hitCount != value)
            {
                _hitCount = value;
                OnPropertyChanged();
            }
        }
    }

    public string Condition
    {
        get => _condition;
        set
        {
            if (_condition != value)
            {
                _condition = value;
                OnPropertyChanged();
            }
        }
    }

    public string StatusText => IsEnabled ? "Enabled" : "Disabled";
    public string TypeDisplay => Type switch
    {
        BreakpointType.Software => "Software (INT3)",
        BreakpointType.HardwareExecute => "HW Execute (DR0-3)",
        BreakpointType.HardwareWrite => "HW Write (Watch)",
        BreakpointType.HardwareReadWrite => "HW Read/Write",
        _ => "Unknown"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}

/// <summary>
/// Register categorization.
/// </summary>
public enum RegisterCategory
{
    GeneralPurpose,
    InstructionPointer,
    Flags,
    Segment,
    SIMD
}

/// <summary>
/// Represents an architecture register in the target execution context.
/// </summary>
public class RegisterModel : INotifyPropertyChanged
{
    private string _valueHex = "0x0000000000000000";
    private string _valueDec = "0";
    private bool _isChanged;
    private ulong _valueUlong;

    public string Name { get; set; } = string.Empty;
    public RegisterCategory Category { get; set; } = RegisterCategory.GeneralPurpose;
    public int BitWidth { get; set; } = 64;
    public string Description { get; set; } = string.Empty;

    public ulong ValueUlong
    {
        get => _valueUlong;
        set
        {
            if (_valueUlong != value)
            {
                _valueUlong = value;
                ValueHex = BitWidth switch
                {
                    8 => $"0x{value:X2}",
                    16 => $"0x{value:X4}",
                    32 => $"0x{value:X8}",
                    _ => $"0x{value:X16}"
                };
                ValueDec = value.ToString();
                IsChanged = true;
                OnPropertyChanged();
            }
        }
    }

    public string ValueHex
    {
        get => _valueHex;
        set
        {
            if (_valueHex != value)
            {
                _valueHex = value;
                OnPropertyChanged();
            }
        }
    }

    public string ValueDec
    {
        get => _valueDec;
        set
        {
            if (_valueDec != value)
            {
                _valueDec = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsChanged
    {
        get => _isChanged;
        set
        {
            if (_isChanged != value)
            {
                _isChanged = value;
                OnPropertyChanged();
            }
        }
    }

    public string CategoryDisplay => Category switch
    {
        RegisterCategory.GeneralPurpose => "General Purpose",
        RegisterCategory.InstructionPointer => "Program Counter (IP)",
        RegisterCategory.Flags => "Status / Flags",
        RegisterCategory.Segment => "Segment",
        RegisterCategory.SIMD => "SIMD / SSE",
        _ => "Other"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}

/// <summary>
/// Represents an entry in the call stack backtrace.
/// </summary>
public class StackFrameModel : INotifyPropertyChanged
{
    public int FrameIndex { get; set; }
    public string InstructionAddress { get; set; } = string.Empty;
    public ulong InstructionVal { get; set; }
    public string FunctionName { get; set; } = string.Empty;
    public string ModuleName { get; set; } = string.Empty;
    public string StackPointer { get; set; } = string.Empty;
    public string FramePointer { get; set; } = string.Empty;
    public string SourceInfo { get; set; } = string.Empty;

    public string FrameTitle => $"#{FrameIndex:D2}  {InstructionAddress}  {ModuleName}!{FunctionName}";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}

/// <summary>
/// Represents an active OS thread inside the debuggee process.
/// </summary>
public class ThreadModel : INotifyPropertyChanged
{
    private string _state = "Running";
    private bool _isCurrent;

    public uint ThreadId { get; set; }
    public string ThreadName { get; set; } = string.Empty;
    public string CurrentAddress { get; set; } = string.Empty;
    public string Priority { get; set; } = "Normal";

    public string State
    {
        get => _state;
        set
        {
            if (_state != value)
            {
                _state = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsCurrent
    {
        get => _isCurrent;
        set
        {
            if (_isCurrent != value)
            {
                _isCurrent = value;
                OnPropertyChanged();
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}

/// <summary>
/// Represents a row of dynamic memory bytes displayed in the live memory inspector.
/// </summary>
public class DebuggerMemoryRow : INotifyPropertyChanged
{
    private string _hexBytes = string.Empty;
    private string _ascii = string.Empty;
    private bool _isCurrentIP;
    private bool _isCurrentSP;

    public string Address { get; set; } = string.Empty;
    public ulong AddressVal { get; set; }

    public string HexBytes
    {
        get => _hexBytes;
        set
        {
            if (_hexBytes != value)
            {
                _hexBytes = value;
                OnPropertyChanged();
            }
        }
    }

    public string Ascii
    {
        get => _ascii;
        set
        {
            if (_ascii != value)
            {
                _ascii = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsCurrentIP
    {
        get => _isCurrentIP;
        set
        {
            if (_isCurrentIP != value)
            {
                _isCurrentIP = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsCurrentSP
    {
        get => _isCurrentSP;
        set
        {
            if (_isCurrentSP != value)
            {
                _isCurrentSP = value;
                OnPropertyChanged();
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? propName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
}
