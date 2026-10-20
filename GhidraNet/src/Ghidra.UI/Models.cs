using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Ghidra.UI.Models;

public class SectionNode : INotifyPropertyChanged
{
    private string _name = string.Empty;
    private string _permissions = string.Empty;
    private ulong _startAddress;
    private ulong _endAddress;
    private long _size;
    private bool _isVolatile;
    private string _blockType = "Initialized";
    private string _comment = string.Empty;
    private string _addressRange = string.Empty;

    public string Name
    {
        get => _name;
        set { if (_name != value) { _name = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayText)); } }
    }

    public string AddressRange
    {
        get => !string.IsNullOrEmpty(_addressRange) ? _addressRange : $"0x{StartAddress:X8} - 0x{EndAddress:X8}";
        set { if (_addressRange != value) { _addressRange = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayText)); } }
    }
    public string StartAddressHex => $"0x{StartAddress:X8}";
    public string EndAddressHex => $"0x{EndAddress:X8}";
    public string SizeHex => $"0x{Size:X}";

    public ulong StartAddress
    {
        get => _startAddress;
        set { if (_startAddress != value) { _startAddress = value; OnPropertyChanged(); OnPropertyChanged(nameof(AddressRange)); OnPropertyChanged(nameof(StartAddressHex)); OnPropertyChanged(nameof(DisplayText)); } }
    }

    public ulong EndAddress
    {
        get => _endAddress;
        set { if (_endAddress != value) { _endAddress = value; OnPropertyChanged(); OnPropertyChanged(nameof(AddressRange)); OnPropertyChanged(nameof(EndAddressHex)); OnPropertyChanged(nameof(DisplayText)); } }
    }

    public uint RawPointer { get; set; }
    public uint VirtualAddress { get; set; }

    public long Size
    {
        get => _size;
        set { if (_size != value) { _size = value; OnPropertyChanged(); OnPropertyChanged(nameof(SizeHex)); } }
    }

    public string Permissions
    {
        get => _permissions;
        set
        {
            if (_permissions != value)
            {
                _permissions = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsReadable));
                OnPropertyChanged(nameof(IsWritable));
                OnPropertyChanged(nameof(IsExecutable));
                OnPropertyChanged(nameof(DisplayText));
            }
        }
    }

    public bool IsReadable
    {
        get => Permissions.Contains("R");
        set => UpdatePermissionChar('R', value);
    }

    public bool IsWritable
    {
        get => Permissions.Contains("W");
        set => UpdatePermissionChar('W', value);
    }

    public bool IsExecutable
    {
        get => Permissions.Contains("X");
        set => UpdatePermissionChar('X', value);
    }

    public bool IsVolatile
    {
        get => _isVolatile;
        set { if (_isVolatile != value) { _isVolatile = value; OnPropertyChanged(); } }
    }

    public string BlockType
    {
        get => _blockType;
        set { if (_blockType != value) { _blockType = value; OnPropertyChanged(); } }
    }

    public string Comment
    {
        get => _comment;
        set { if (_comment != value) { _comment = value; OnPropertyChanged(); } }
    }

    private void UpdatePermissionChar(char c, bool enable)
    {
        string p = Permissions;
        if (enable && !p.Contains(c)) p += c;
        else if (!enable && p.Contains(c)) p = p.Replace(c.ToString(), "");
        Permissions = p;
    }

    public byte[] Data { get; set; } = Array.Empty<byte>();
    public string DisplayText => $"{Name} [{AddressRange}] ({Permissions})";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class SymbolNode : INotifyPropertyChanged
{
    private string _name = string.Empty;
    private string _signature = string.Empty;

    public string Name
    {
        get => _name;
        set
        {
            if (_name != value)
            {
                _name = value;
                OnPropertyChanged();
            }
        }
    }

    public string Address { get; set; } = string.Empty;
    public string SymbolType { get; set; } = string.Empty; // Function, Import, Export, Label

    public string Signature
    {
        get => _signature;
        set
        {
            if (_signature != value)
            {
                _signature = value;
                OnPropertyChanged();
            }
        }
    }

    public string Icon { get; set; } = "⚡";

    public ObservableCollection<SymbolNode> Children { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class DataTypeNode : INotifyPropertyChanged
{
    public string Name { get; set; } = string.Empty;
    public string Size { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty; // Struct, Enum, Typedef, BuiltIn, Category
    public string Icon { get; set; } = "📁";

    public ObservableCollection<DataTypeNode> Children { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ByteViewerRow : INotifyPropertyChanged
{
    private bool _isModified;
    public string Address { get; set; } = string.Empty;
    public string Hex0_3 { get; set; } = string.Empty;
    public string Hex4_7 { get; set; } = string.Empty;
    public string Hex8_B { get; set; } = string.Empty;
    public string HexC_F { get; set; } = string.Empty;
    public string Ascii { get; set; } = string.Empty;

    public bool IsModified
    {
        get => _isModified;
        set
        {
            if (_isModified != value)
            {
                _isModified = value;
                OnPropertyChanged();
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class StructFieldModel : INotifyPropertyChanged
{
    private int _offset;
    private string _name = "field";
    private string _typeName = "int32";
    private int _size = 4;
    private string _comment = string.Empty;

    public int Offset
    {
        get => _offset;
        set
        {
            if (_offset != value)
            {
                _offset = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(OffsetHex));
            }
        }
    }
    public string OffsetHex => $"0x{Offset:X2}";

    public string Name
    {
        get => _name;
        set { if (_name != value) { _name = value; OnPropertyChanged(); } }
    }

    public string TypeName
    {
        get => _typeName;
        set { if (_typeName != value) { _typeName = value; OnPropertyChanged(); } }
    }

    public int Size
    {
        get => _size;
        set { if (_size != value) { _size = value; OnPropertyChanged(); } }
    }

    public string Comment
    {
        get => _comment;
        set { if (_comment != value) { _comment = value; OnPropertyChanged(); } }
    }

    public string DisplayText => $"{OffsetHex} : {TypeName} {Name}; // {Comment}";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class CustomStructModel : INotifyPropertyChanged
{
    private string _name = "CustomStruct";
    public string Name
    {
        get => _name;
        set { if (_name != value) { _name = value; OnPropertyChanged(); } }
    }

    public ObservableCollection<StructFieldModel> Fields { get; set; } = new();

    public int TotalSize => Fields.Count > 0 ? Fields.Max(f => f.Offset + f.Size) : 0;

    public string GenerateCHeader()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"typedef struct _{Name} {{");
        foreach (var f in Fields.OrderBy(f => f.Offset))
        {
            string cmt = string.IsNullOrEmpty(f.Comment) ? "" : $" // {f.Comment}";
            sb.AppendLine($"    {f.TypeName,-12} {f.Name,-16}; /* +0x{f.Offset:X2} (size: {f.Size}) */{cmt}");
        }
        sb.AppendLine($"}} {Name}, *P{Name};");
        return sb.ToString();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class XRefModel : INotifyPropertyChanged
{
    public ulong FromAddress { get; set; }
    public string RefType { get; set; } = "CALL"; // CALL, JUMP, DATA, IAT
    public string InstructionText { get; set; } = string.Empty;
    public string FunctionContext { get; set; } = string.Empty;
    public string DisplayText => $"0x{FromAddress:X8}  [{RefType}]  {InstructionText}";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ListingItem : INotifyPropertyChanged
{
    private bool _isSelected;
    private bool _isHighlighted;
    private string _comment = string.Empty;
    private string _functionName = string.Empty;
    private string _operands = string.Empty;
    private string _instruction = string.Empty;

    public string Address { get; set; } = string.Empty;
    public string Bytes { get; set; } = string.Empty;

    public string Instruction
    {
        get => _instruction;
        set
        {
            if (_instruction != value)
            {
                _instruction = value;
                OnPropertyChanged();
            }
        }
    }

    public string Operands
    {
        get => _operands;
        set
        {
            if (_operands != value)
            {
                _operands = value;
                OnPropertyChanged();
            }
        }
    }

    public string Comment
    {
        get => _comment;
        set
        {
            if (_comment != value)
            {
                _comment = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsFunctionHeader { get; set; }

    public string FunctionName
    {
        get => _functionName;
        set
        {
            if (_functionName != value)
            {
                _functionName = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                OnPropertyChanged();
            }
        }
    }

    public bool IsHighlighted
    {
        get => _isHighlighted;
        set
        {
            if (_isHighlighted != value)
            {
                _isHighlighted = value;
                OnPropertyChanged();
            }
        }
    }

    private bool _isPatched;
    public bool IsPatched
    {
        get => _isPatched;
        set
        {
            if (_isPatched != value)
            {
                _isPatched = value;
                OnPropertyChanged();
            }
        }
    }

    private bool _isBookmarked;
    public bool IsBookmarked
    {
        get => _isBookmarked;
        set
        {
            if (_isBookmarked != value)
            {
                _isBookmarked = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(BookmarkIcon));
            }
        }
    }

    private string _bookmarkText = string.Empty;
    public string BookmarkText
    {
        get => _bookmarkText;
        set
        {
            if (_bookmarkText != value)
            {
                _bookmarkText = value;
                OnPropertyChanged();
            }
        }
    }

    public string BookmarkCategory { get; set; } = "Note";

    private bool _isBreakpoint;
    public bool IsBreakpoint
    {
        get => _isBreakpoint;
        set
        {
            if (_isBreakpoint != value)
            {
                _isBreakpoint = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(GutterIcon));
                OnPropertyChanged(nameof(BookmarkIcon));
            }
        }
    }

    private bool _isCurrentIP;
    public bool IsCurrentIP
    {
        get => _isCurrentIP;
        set
        {
            if (_isCurrentIP != value)
            {
                _isCurrentIP = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(GutterIcon));
                OnPropertyChanged(nameof(BookmarkIcon));
            }
        }
    }

    public string GutterIcon
    {
        get
        {
            if (IsBreakpoint && IsCurrentIP) return "🔴👉";
            if (IsCurrentIP) return "👉";
            if (IsBreakpoint) return "🔴";
            return BookmarkIcon;
        }
    }

    public string BookmarkIcon
    {
        get
        {
            if (IsBreakpoint && IsCurrentIP) return "🔴👉";
            if (IsCurrentIP) return "👉";
            if (IsBreakpoint) return "🔴";
            if (!IsBookmarked) return string.Empty;
            return BookmarkCategory switch
            {
                "Warning" => "⚠️",
                "Error" => "❌",
                "Info" => "ℹ️",
                _ => "🔖"
            };
        }
    }

    private string _preComment = string.Empty;
    public string PreComment
    {
        get => _preComment;
        set
        {
            if (_preComment != value)
            {
                _preComment = value;
                OnPropertyChanged();
            }
        }
    }

    private string _flowArrow = string.Empty;
    public string FlowArrow
    {
        get => _flowArrow;
        set
        {
            if (_flowArrow != value)
            {
                _flowArrow = value;
                OnPropertyChanged();
            }
        }
    }

    private string _fallthroughText = string.Empty;
    public string FallthroughText
    {
        get => _fallthroughText;
        set
        {
            if (_fallthroughText != value)
            {
                _fallthroughText = value;
                OnPropertyChanged();
            }
        }
    }

    public ulong? FallthroughOverrideAddress { get; set; }
    public string FlowArrowColor => FlowArrow.Contains("↻") ? "#F59E0B" : (FlowArrow.Contains("↓") ? "#10B981" : (FlowArrow.Contains("➔") ? "#6366F1" : (FlowArrow.Contains("⮌") ? "#EF4444" : "#64748B")));
    public string FallthroughColor => FallthroughText.Contains("No") ? "#EF4444" : "#8B5CF6";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ProgramModel : INotifyPropertyChanged
{
    public string ProgramName { get; set; } = "decompile.exe";
    public string FilePath { get; set; } = string.Empty;
    public string Format { get; set; } = "PE (Portable Executable 64-bit)";
    public string Architecture { get; set; } = "x86_64:LE:64:default";
    public string Compiler { get; set; } = "Visual Studio (MSVC x64)";
    public ulong ImageBase { get; set; } = 0x00400000;
    public ulong EntryPoint { get; set; } = 0x00401000;
    public bool Is64Bit { get; set; } = true;
    public string StatusMessage { get; set; } = string.Empty;

    public Dictionary<ulong, string> IatMap { get; set; } = new();
    public Dictionary<ulong, string> StringMap { get; set; } = new();
    public HashSet<ulong> FunctionAddresses { get; set; } = new();
    public Dictionary<ulong, List<XRefModel>> XRefs { get; set; } = new();
    public Dictionary<ulong, string> CustomComments { get; set; } = new();
    public Dictionary<string, string> RenamedSymbols { get; set; } = new();
    public Dictionary<ulong, byte> PatchedBytes { get; set; } = new();
    public ObservableCollection<CustomStructModel> CustomStructures { get; set; } = new();
    public Dictionary<ulong, string> AppliedTypes { get; set; } = new();

    public byte[] CodeBytes { get; set; } = Array.Empty<byte>();
    public ulong CodeBaseAddr { get; set; }

    public ObservableCollection<SectionNode> Sections { get; set; } = new();
    public ObservableCollection<SymbolNode> SymbolCategories { get; set; } = new();
    public ObservableCollection<DataTypeNode> DataTypeCategories { get; set; } = new();
    public ObservableCollection<ByteViewerRow> ByteViewerRows { get; set; } = new();
    public ObservableCollection<ListingItem> ListingLines { get; set; } = new();
    public ObservableCollection<BookmarkItem> Bookmarks { get; set; } = new();
    public ObservableCollection<CustomEnumModel> CustomEnums { get; set; } = new();
    public ObservableCollection<ProgramTreeNode> ProgramTreeNodes { get; set; } = new();
    public ControlFlowGraph? CurrentGraph { get; set; }

    // Tier 1 Enhancements: CallTree, PCode, Equates
    public Dictionary<ulong, string> AppliedEquates { get; set; } = new(); // Address -> Equate Name
    public ObservableCollection<EquateModel> Equates { get; set; } = new();
    public ObservableCollection<CallTreeNode> IncomingCalls { get; set; } = new();
    public ObservableCollection<CallTreeNode> OutgoingCalls { get; set; } = new();
    public ObservableCollection<PcodeOpModel> CurrentPcodeOps { get; set; } = new();

    // Tier 2 Enhancements: Fallthrough, Entropy, PDB, Scripts
    public Dictionary<ulong, ulong?> FallthroughOverrides { get; set; } = new();
    public ObservableCollection<SectionEntropyModel> SectionEntropies { get; set; } = new();
    public ObservableCollection<EntropyBlockModel> EntropyBlocks { get; set; } = new();
    public PdbInfoModel? PdbInfo { get; set; }
    public ObservableCollection<ScriptItemModel> Scripts { get; set; } = new();

    public SectionNode? FindSection(ulong address)
    {
        return Sections.FirstOrDefault(s => address >= s.StartAddress && address < s.EndAddress);
    }

    public byte[]? GetSectionData(ulong address, out ulong offsetInSection)
    {
        var sec = FindSection(address);
        if (sec != null && sec.Data != null && sec.Data.Length > 0 && address >= sec.StartAddress)
        {
            offsetInSection = address - sec.StartAddress;
            return sec.Data;
        }
        offsetInSection = 0;
        return null;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class BookmarkItem : INotifyPropertyChanged
{
    private string _description = string.Empty;
    private string _category = "Note";

    public ulong Address { get; set; }
    public string AddressHex => $"0x{Address:X8}";
    public string FunctionName { get; set; } = string.Empty;

    public string Category
    {
        get => _category;
        set
        {
            if (_category != value)
            {
                _category = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(Icon));
            }
        }
    }

    public string Description
    {
        get => _description;
        set
        {
            if (_description != value)
            {
                _description = value;
                OnPropertyChanged();
            }
        }
    }

    public string Icon => Category switch
    {
        "Warning" => "⚠️",
        "Error" => "❌",
        "Info" => "ℹ️",
        _ => "🔖"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class EnumMemberModel : INotifyPropertyChanged
{
    private string _name = "MEMBER_0";
    private long _value = 0;
    private string _comment = string.Empty;

    public string Name
    {
        get => _name;
        set { if (_name != value) { _name = value; OnPropertyChanged(); } }
    }

    public long Value
    {
        get => _value;
        set
        {
            if (_value != value)
            {
                _value = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ValueHex));
                OnPropertyChanged(nameof(DisplayText));
            }
        }
    }

    public string ValueHex => $"0x{Value:X}";

    public string Comment
    {
        get => _comment;
        set { if (_comment != value) { _comment = value; OnPropertyChanged(); OnPropertyChanged(nameof(DisplayText)); } }
    }

    public string DisplayText => string.IsNullOrEmpty(Comment) ? $"{Name} = {ValueHex}" : $"{Name} = {ValueHex} // {Comment}";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class CustomEnumModel : INotifyPropertyChanged
{
    private string _name = "CustomEnum";
    private string _underlyingType = "uint32";

    public string Name
    {
        get => _name;
        set { if (_name != value) { _name = value; OnPropertyChanged(); } }
    }

    public string UnderlyingType
    {
        get => _underlyingType;
        set { if (_underlyingType != value) { _underlyingType = value; OnPropertyChanged(); } }
    }

    public ObservableCollection<EnumMemberModel> Members { get; set; } = new();

    public string GenerateCHeader()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"typedef enum _{Name} {{");
        foreach (var m in Members)
        {
            string cmt = string.IsNullOrEmpty(m.Comment) ? "" : $" // {m.Comment}";
            sb.AppendLine($"    {m.Name,-24} = {m.ValueHex},{cmt}");
        }
        sb.AppendLine($"}} {Name};");
        return sb.ToString();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ProgramTreeNode : INotifyPropertyChanged
{
    public string Name { get; set; } = string.Empty;
    public string Icon { get; set; } = "📁";
    public string AddressRange { get; set; } = string.Empty;
    public ulong StartAddress { get; set; }
    public string Permissions { get; set; } = string.Empty;
    public string SizeInfo { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;

    public ObservableCollection<ProgramTreeNode> Children { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public enum SearchResultType
{
    String,
    HexBytes,
    Scalar
}

public class SearchResultItem : INotifyPropertyChanged
{
    public SearchResultType ResultType { get; set; }
    public ulong Address { get; set; }
    public string AddressHex => $"0x{Address:X8}";
    public string SectionName { get; set; } = string.Empty;
    public string Preview { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;

    public string TypeIcon => ResultType switch
    {
        SearchResultType.String => "🔤",
        SearchResultType.HexBytes => "🔍",
        SearchResultType.Scalar => "🔢",
        _ => "🔎"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class BasicBlock : INotifyPropertyChanged
{
    private double _x;
    private double _y;
    private double _width = 280;
    private double _height = 120;
    private bool _isSelected;

    public int Id { get; set; }
    public ulong StartAddress { get; set; }
    public ulong EndAddress { get; set; }
    public string Label { get; set; } = string.Empty;
    public int Layer { get; set; }
    public int OrderInLayer { get; set; }

    public bool IsEntryBlock { get; set; }
    public bool IsReturnBlock { get; set; }

    public string HeaderBackground => IsEntryBlock ? "#DCFCE7" : (IsReturnBlock ? "#FEF3C7" : "#F1F5F9");
    public string HeaderForeground => IsEntryBlock ? "#166534" : (IsReturnBlock ? "#92400E" : "#1E293B");
    public string BorderColor => IsSelected ? "#2563EB" : (IsEntryBlock ? "#86EFAC" : "#CBD5E1");
    public double BorderThickness => IsSelected ? 2.5 : 1.0;

    public ObservableCollection<ListingItem> Instructions { get; set; } = new();

    public List<int> Successors { get; set; } = new();
    public List<int> Predecessors { get; set; } = new();

    public double X
    {
        get => _x;
        set { if (_x != value) { _x = value; OnPropertyChanged(); } }
    }

    public double Y
    {
        get => _y;
        set { if (_y != value) { _y = value; OnPropertyChanged(); } }
    }

    public double Width
    {
        get => _width;
        set { if (_width != value) { _width = value; OnPropertyChanged(); } }
    }

    public double Height
    {
        get => _height;
        set { if (_height != value) { _height = value; OnPropertyChanged(); } }
    }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected != value)
            {
                _isSelected = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(BorderColor));
                OnPropertyChanged(nameof(BorderThickness));
            }
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public enum EdgeType
{
    Unconditional,
    TrueBranch,
    FalseBranch,
    Call
}

public class GraphEdge : INotifyPropertyChanged
{
    public int FromBlockId { get; set; }
    public int ToBlockId { get; set; }
    public EdgeType Type { get; set; }

    public string StrokeColor => Type switch
    {
        EdgeType.TrueBranch => "#16A34A",   // Emerald Green
        EdgeType.FalseBranch => "#DC2626",  // Crimson Red
        EdgeType.Call => "#8B5CF6",         // Purple
        _ => "#2563EB"                      // Royal Blue
    };

    public double StrokeThickness => 2.0;

    public double StartX { get; set; }
    public double StartY { get; set; }
    public double EndX { get; set; }
    public double EndY { get; set; }

    public string ArrowHeadData { get; set; } = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ControlFlowGraph : INotifyPropertyChanged
{
    public ulong FunctionEntry { get; set; }
    public string FunctionName { get; set; } = string.Empty;
    public ObservableCollection<BasicBlock> Blocks { get; set; } = new();
    public ObservableCollection<GraphEdge> Edges { get; set; } = new();

    public double CanvasWidth { get; set; } = 1200;
    public double CanvasHeight { get; set; } = 900;

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

// =========================================================================
// Tier 1 Enhancements Models: Call Tree, P-Code, Equate, Function Diff
// =========================================================================

public class CallTreeNode : INotifyPropertyChanged
{
    private bool _isExpanded = true;
    public string FunctionName { get; set; } = string.Empty;
    public ulong Address { get; set; }
    public string AddressHex => $"0x{Address:X8}";
    public ulong CallSiteAddress { get; set; }
    public string CallSiteAddressHex => CallSiteAddress != 0 ? $"0x{CallSiteAddress:X8}" : string.Empty;
    public string InstructionPreview { get; set; } = string.Empty;
    public string Icon { get; set; } = "⚡";
    public ObservableCollection<CallTreeNode> Children { get; set; } = new();

    public bool IsExpanded
    {
        get => _isExpanded;
        set { if (_isExpanded != value) { _isExpanded = value; OnPropertyChanged(); } }
    }

    public string DisplayText => CallSiteAddress != 0
        ? $"{FunctionName} [from {CallSiteAddressHex}: {InstructionPreview}]"
        : $"{FunctionName} @ {AddressHex}";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class PcodeOpModel : INotifyPropertyChanged
{
    public ulong Address { get; set; }
    public string AddressHex => $"0x{Address:X8}";
    public int Sequence { get; set; }
    public string InstructionText { get; set; } = string.Empty;
    public string Opcode { get; set; } = string.Empty;
    public string Output { get; set; } = string.Empty;
    public string Inputs { get; set; } = string.Empty;
    public string FullText => string.IsNullOrEmpty(Output) ? $"{Opcode} {Inputs}" : $"{Output} = {Opcode} {Inputs}";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class EquateModel : INotifyPropertyChanged
{
    private string _name = string.Empty;
    private ulong _value;
    private string _category = "General";

    public string Name
    {
        get => _name;
        set { if (_name != value) { _name = value; OnPropertyChanged(); } }
    }

    public ulong Value
    {
        get => _value;
        set
        {
            if (_value != value)
            {
                _value = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(ValueHex));
                OnPropertyChanged(nameof(ValueDec));
            }
        }
    }

    public string ValueHex => $"0x{Value:X}";
    public string ValueDec => $"{Value}";

    public string Category
    {
        get => _category;
        set { if (_category != value) { _category = value; OnPropertyChanged(); } }
    }

    public ObservableCollection<ulong> ReferenceAddresses { get; set; } = new();
    public int RefCount => ReferenceAddresses.Count;
    public string RefCountText => $"{RefCount} ref(s)";
    public string AddressesSummary => string.Join(", ", ReferenceAddresses.Select(a => $"0x{a:X8}"));

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public enum DiffLineKind
{
    Same,
    Modified,
    Added,
    Deleted
}

public class DiffLineModel : INotifyPropertyChanged
{
    public int LineNumber { get; set; }
    public string AddressHex { get; set; } = string.Empty;
    public string Text { get; set; } = string.Empty;
    public DiffLineKind Kind { get; set; } = DiffLineKind.Same;

    public string BackgroundColor => Kind switch
    {
        DiffLineKind.Modified => "#FEF9C3", // Light Yellow
        DiffLineKind.Added => "#DCFCE7",    // Light Green
        DiffLineKind.Deleted => "#FEE2E2",  // Light Red
        _ => "Transparent"
    };

    public string ForegroundColor => Kind switch
    {
        DiffLineKind.Modified => "#854D0E",
        DiffLineKind.Added => "#166534",
        DiffLineKind.Deleted => "#991B1B",
        _ => "#0F172A"
    };

    public string KindTag => Kind switch
    {
        DiffLineKind.Modified => "MOD",
        DiffLineKind.Added => "+",
        DiffLineKind.Deleted => "-",
        _ => " "
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

// =========================================================================
// Tier 2 Enhancements Models: Entropy, PDB, Scripts
// =========================================================================

public class EntropyBlockModel : INotifyPropertyChanged
{
    public ulong Address { get; set; }
    public string AddressHex => $"0x{Address:X8}";
    public double Entropy { get; set; }
    public string SectionName { get; set; } = string.Empty;
    public double BarHeight => Math.Max(2.0, (Entropy / 8.0) * 120.0);
    public string RiskColor => Entropy >= 6.8 ? "#EF4444" : (Entropy >= 5.0 ? "#10B981" : "#3B82F6");
    public string RiskLevel => Entropy >= 6.8 ? "Packed/Encrypted" : (Entropy >= 5.0 ? "Code/Data" : "Sparse/Low");

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class SectionEntropyModel : INotifyPropertyChanged
{
    public string Name { get; set; } = string.Empty;
    public ulong StartAddress { get; set; }
    public string StartAddressHex => $"0x{StartAddress:X8}";
    public ulong EndAddress { get; set; }
    public string EndAddressHex => $"0x{EndAddress:X8}";
    public long Size { get; set; }
    public string SizeHex => $"0x{Size:X}";
    public double Entropy { get; set; }
    public string EntropyText => $"{Entropy:F2} / 8.0";
    public string Status { get; set; } = "Normal";

    public string StatusColor => Status switch
    {
        "Packed / Encrypted" => "#DC2626",
        "Normal (Executable Code)" => "#16A34A",
        "Normal (Data / Strings)" => "#2563EB",
        _ => "#475569"
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class PdbInfoModel : INotifyPropertyChanged
{
    public bool HasCodeView { get; set; }
    public string PdbPath { get; set; } = string.Empty;
    public string PdbFileName => System.IO.Path.GetFileName(PdbPath);
    public Guid Guid { get; set; }
    public uint Age { get; set; }
    public string GuidAgeString => $"{Guid:N}{Age}".ToUpperInvariant();
    public string SymbolServerUrl => $"https://msdl.microsoft.com/download/symbols/{PdbFileName}/{GuidAgeString}/{PdbFileName}";
    public int DiscoveredSymbolsCount { get; set; }
    public string Status { get; set; } = "Not Loaded";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ScriptItemModel : INotifyPropertyChanged
{
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = "General";
    public string Description { get; set; } = string.Empty;
    public string ScriptCode { get; set; } = string.Empty;
    public string Icon { get; set; } = "📜";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
