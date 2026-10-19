using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace Ghidra.UI.Models;

public class SectionNode : INotifyPropertyChanged
{
    public string Name { get; set; } = string.Empty;
    public string AddressRange { get; set; } = string.Empty;
    public long Size { get; set; }
    public string Permissions { get; set; } = string.Empty;
    public string DisplayText => $"{Name} [{AddressRange}] ({Permissions})";

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class SymbolNode : INotifyPropertyChanged
{
    public string Name { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string SymbolType { get; set; } = string.Empty; // Function, Import, Export, Label
    public string Signature { get; set; } = string.Empty;
    public string Icon { get; set; } = "⚡";

    public ObservableCollection<SymbolNode> Children { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public class ListingItem : INotifyPropertyChanged
{
    private bool _isSelected;

    public string Address { get; set; } = string.Empty;
    public string Bytes { get; set; } = string.Empty;
    public string Instruction { get; set; } = string.Empty;
    public string Operands { get; set; } = string.Empty;
    public string Comment { get; set; } = string.Empty;
    public bool IsFunctionHeader { get; set; }
    public string FunctionName { get; set; } = string.Empty;

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

    public ObservableCollection<SectionNode> Sections { get; set; } = new();
    public ObservableCollection<SymbolNode> SymbolCategories { get; set; } = new();
    public ObservableCollection<ListingItem> ListingLines { get; set; } = new();

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
