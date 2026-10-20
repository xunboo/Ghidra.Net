using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using Ghidra.UI.Models;
using Ghidra.UI.Services;

namespace Ghidra.UI.Dialogs;

public class PromptDialog : Window
{
    private TextBox _inputBox;
    public string ResultText { get; private set; } = string.Empty;
    public string InputText => ResultText;

    public PromptDialog(string title, string prompt, string initialValue)
    {
        Title = title;
        Width = 460;
        Height = 200;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        ResizeMode = ResizeMode.NoResize;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var mainPanel = new StackPanel { Margin = new Thickness(16) };

        var lblPrompt = new TextBlock
        {
            Text = prompt,
            FontWeight = FontWeights.SemiBold,
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.FromRgb(0x1E, 0x29, 0x3B)),
            Margin = new Thickness(0, 0, 0, 10)
        };
        mainPanel.Children.Add(lblPrompt);

        _inputBox = new TextBox
        {
            Text = initialValue,
            Padding = new Thickness(8, 6, 8, 6),
            FontSize = 13,
            FontFamily = new FontFamily("Consolas"),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            Background = Brushes.White,
            Margin = new Thickness(0, 0, 0, 16)
        };
        _inputBox.KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) { Confirm(); }
            else if (e.Key == Key.Escape) { DialogResult = false; Close(); }
        };
        mainPanel.Children.Add(_inputBox);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

        var btnOk = new Button
        {
            Content = "OK (Enter)",
            Width = 90,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnOk.Click += (s, e) => Confirm();
        btnPanel.Children.Add(btnOk);

        var btnCancel = new Button
        {
            Content = "Cancel",
            Width = 80,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        mainPanel.Children.Add(btnPanel);
        Content = mainPanel;

        Loaded += (s, e) =>
        {
            _inputBox.Focus();
            _inputBox.SelectAll();
        };
    }

    private void Confirm()
    {
        ResultText = _inputBox.Text.Trim();
        DialogResult = true;
        Close();
    }
}

public class XRefsWindow : Window
{
    private ListView _lvRefs;
    private Action<ulong>? _onNavigate;

    public XRefsWindow(string symbolName, ulong address, List<XRefModel> refs, Action<ulong>? onNavigate)
    {
        _onNavigate = onNavigate;
        Title = $"Cross References (XREFs) to {symbolName} [0x{address:X8}]";
        Width = 750;
        Height = 440;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Header info
        var headerBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x02, 0x84, 0xC7)),
            Padding = new Thickness(12, 10, 12, 10)
        };
        var headerText = new TextBlock
        {
            Text = $"Cross-References to {symbolName} @ 0x{address:X8} (Total: {refs.Count} references)\nDouble-click any reference or press Enter to navigate to call site.",
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            FontSize = 13
        };
        headerBorder.Child = headerText;
        Grid.SetRow(headerBorder, 0);
        grid.Children.Add(headerBorder);

        // ListView
        _lvRefs = new ListView
        {
            ItemsSource = refs,
            FontFamily = new FontFamily("Cascadia Code, Consolas"),
            FontSize = 12,
            BorderThickness = new Thickness(0),
            Background = Brushes.White
        };

        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "From Address", Width = 130, DisplayMemberBinding = new System.Windows.Data.Binding("FromAddress") { StringFormat = "0x{0:X8}" } });
        gv.Columns.Add(new GridViewColumn { Header = "Type", Width = 80, DisplayMemberBinding = new System.Windows.Data.Binding("RefType") });
        gv.Columns.Add(new GridViewColumn { Header = "Instruction", Width = 260, DisplayMemberBinding = new System.Windows.Data.Binding("InstructionText") });
        gv.Columns.Add(new GridViewColumn { Header = "Calling Context", Width = 220, DisplayMemberBinding = new System.Windows.Data.Binding("FunctionContext") });
        _lvRefs.View = gv;

        _lvRefs.MouseDoubleClick += (s, e) => JumpSelected();
        _lvRefs.KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) JumpSelected();
            else if (e.Key == Key.Escape) Close();
        };

        Grid.SetRow(_lvRefs, 1);
        grid.Children.Add(_lvRefs);

        // Footer buttons
        var footer = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(10)
        };
        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

        var btnJump = new Button
        {
            Content = "Jump to Reference (Enter)",
            Width = 180,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnJump.Click += (s, e) => JumpSelected();
        btnPanel.Children.Add(btnJump);

        var btnClose = new Button
        {
            Content = "Close (Esc)",
            Width = 90,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55))
        };
        btnClose.Click += (s, e) => Close();
        btnPanel.Children.Add(btnClose);

        footer.Child = btnPanel;
        Grid.SetRow(footer, 2);
        grid.Children.Add(footer);

        Content = grid;
    }

    private void JumpSelected()
    {
        if (_lvRefs.SelectedItem is XRefModel xrf)
        {
            _onNavigate?.Invoke(xrf.FromAddress);
            Close();
        }
    }
}

public class PatchInstructionDialog : Window
{
    private TextBox _txtAsm;
    private TextBox _txtHex;
    private TextBlock _lblPreview;
    private TextBlock _lblDecoded;
    private CheckBox _chkPadNops;
    private ComboBox _cmbPresets;
    private ulong _address;
    private int _origByteCount;
    private bool _updatingAsm;
    private bool _updatingHex;

    public byte[] ResultBytes { get; private set; } = Array.Empty<byte>();

    public PatchInstructionDialog(ulong address, string originalBytes, string originalInstruction)
    {
        _address = address;
        _origByteCount = Math.Max(1, originalBytes.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Length);

        Title = $"Interactive Assembler & Byte Patch @ 0x{address:X8}";
        Width = 600;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        ResizeMode = ResizeMode.NoResize;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var mainPanel = new StackPanel { Margin = new Thickness(16) };

        // 1. Header info
        var infoBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xEE, 0xF2, 0xF6)),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(10),
            Margin = new Thickness(0, 0, 0, 10)
        };
        var infoText = new TextBlock
        {
            Text = $"Address: 0x{address:X8}\nOriginal: {originalInstruction}\nOriginal Bytes: {originalBytes} ({_origByteCount} bytes)",
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55))
        };
        infoBorder.Child = infoText;
        mainPanel.Children.Add(infoBorder);

        // 2. Presets selector
        var lblPreset = new TextBlock { Text = "⚡ Quick Patch Templates:", FontWeight = FontWeights.SemiBold, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblPreset);

        _cmbPresets = new ComboBox { Margin = new Thickness(0, 0, 0, 10), Padding = new Thickness(4) };
        _cmbPresets.Items.Add("-- Choose Preset / Template --");
        _cmbPresets.Items.Add("Fill Entire Instruction with NOPs (0x90)");
        _cmbPresets.Items.Add("Return 1 / TRUE (MOV EAX, 1; RET)");
        _cmbPresets.Items.Add("Return 0 / FALSE (XOR EAX, EAX; RET)");
        _cmbPresets.Items.Add("Force Return (RET)");
        _cmbPresets.Items.Add("Breakpoint Trap (INT 3)");
        _cmbPresets.Items.Add("Infinite Loop (EB FE)");
        _cmbPresets.SelectedIndex = 0;
        _cmbPresets.SelectionChanged += (s, e) =>
        {
            if (_cmbPresets.SelectedIndex <= 0) return;
            switch (_cmbPresets.SelectedIndex)
            {
                case 1:
                    _txtAsm.Text = $"NOP {_origByteCount}";
                    break;
                case 2:
                    _txtAsm.Text = "MOV EAX, 1; RET";
                    break;
                case 3:
                    _txtAsm.Text = "XOR EAX, EAX; RET";
                    break;
                case 4:
                    _txtAsm.Text = "RET";
                    break;
                case 5:
                    _txtAsm.Text = "INT 3";
                    break;
                case 6:
                    _txtHex.Text = "EB FE";
                    break;
            }
        };
        mainPanel.Children.Add(_cmbPresets);

        // 3. Assembly Text Input
        var lblAsm = new TextBlock { Text = "⌨️ Live Assembly Instruction(s) (Mnemonics):", FontWeight = FontWeights.SemiBold, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblAsm);

        _txtAsm = new TextBox
        {
            Text = originalInstruction,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 13,
            Padding = new Thickness(8, 6, 8, 6),
            Margin = new Thickness(0, 0, 0, 10),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1))
        };
        _txtAsm.TextChanged += (s, e) =>
        {
            if (_updatingHex) return;
            _updatingAsm = true;
            try
            {
                var asmRes = X86AssemblerService.Assemble(_txtAsm.Text, _address);
                if (asmRes.Success && asmRes.Bytes.Length > 0)
                {
                    _txtHex.Text = BitConverter.ToString(asmRes.Bytes).Replace("-", " ");
                    _lblDecoded.Text = $"Decoded: {asmRes.DecodedPreview.Replace("\r\n", " | ").Replace("\n", " | ")}";
                    _lblDecoded.Foreground = new SolidColorBrush(Color.FromRgb(0x16, 0x65, 0x34));
                }
                else
                {
                    _lblDecoded.Text = $"Assembler: {asmRes.ErrorMessage}";
                    _lblDecoded.Foreground = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26));
                }
            }
            finally
            {
                _updatingAsm = false;
            }
            UpdatePreview();
        };
        mainPanel.Children.Add(_txtAsm);

        // 4. Hex Input
        var lblHex = new TextBlock { Text = "🔢 Machine Code Hex Bytes (space separated):", FontWeight = FontWeights.SemiBold, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblHex);

        _txtHex = new TextBox
        {
            Text = originalBytes,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 13,
            Padding = new Thickness(8, 6, 8, 6),
            Margin = new Thickness(0, 0, 0, 6),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1))
        };
        _txtHex.TextChanged += (s, e) =>
        {
            if (_updatingAsm) return;
            _updatingHex = true;
            try
            {
                UpdatePreview();
            }
            finally
            {
                _updatingHex = false;
            }
        };
        mainPanel.Children.Add(_txtHex);

        // 5. NOP padding checkbox
        _chkPadNops = new CheckBox
        {
            Content = $"Pad remaining bytes with NOPs (0x90) to match original length ({_origByteCount} bytes)",
            IsChecked = true,
            Margin = new Thickness(0, 0, 0, 8),
            Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69))
        };
        _chkPadNops.Checked += (s, e) => UpdatePreview();
        _chkPadNops.Unchecked += (s, e) => UpdatePreview();
        mainPanel.Children.Add(_chkPadNops);

        // 6. Preview label
        _lblPreview = new TextBlock
        {
            Text = "Preview: ...",
            FontStyle = FontStyles.Italic,
            Foreground = new SolidColorBrush(Color.FromRgb(0x02, 0x84, 0xC7)),
            FontFamily = new FontFamily("Consolas"),
            Margin = new Thickness(0, 0, 0, 4)
        };
        mainPanel.Children.Add(_lblPreview);

        _lblDecoded = new TextBlock
        {
            Text = "Decoded: Ready",
            FontSize = 11,
            FontFamily = new FontFamily("Consolas"),
            Foreground = new SolidColorBrush(Color.FromRgb(0x16, 0x65, 0x34)),
            Margin = new Thickness(0, 0, 0, 14)
        };
        mainPanel.Children.Add(_lblDecoded);

        // 7. Buttons
        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnApply = new Button
        {
            Content = "Apply Patch (Enter)",
            Width = 140,
            Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnApply.Click += (s, e) => Apply();
        btnPanel.Children.Add(btnApply);

        var btnCancel = new Button
        {
            Content = "Cancel (Esc)",
            Width = 90,
            Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        mainPanel.Children.Add(btnPanel);
        Content = mainPanel;

        KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) Apply();
            else if (e.Key == Key.Escape) { DialogResult = false; Close(); }
        };

        UpdatePreview();
        Loaded += (s, e) => { _txtAsm.Focus(); _txtAsm.SelectAll(); };
    }

    private void UpdatePreview()
    {
        var bytes = ParseBytes(_txtHex.Text);
        if (_chkPadNops != null && _chkPadNops.IsChecked == true && bytes.Length < _origByteCount)
        {
            int diff = _origByteCount - bytes.Length;
            var padded = new List<byte>(bytes);
            padded.AddRange(Enumerable.Repeat((byte)0x90, diff));
            bytes = padded.ToArray();
        }

        if (bytes.Length > 0)
        {
            string byteStr = string.Join(" ", bytes.Select(b => $"{b:X2}"));
            _lblPreview.Text = $"Final Bytes ({bytes.Length} B): {byteStr}";
        }
        else
        {
            _lblPreview.Text = "Please enter valid assembly or hex bytes";
        }
    }

    private static byte[] ParseBytes(string hexStr)
    {
        var parts = hexStr.Split(new[] { ' ', ',', '-', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        var list = new List<byte>();
        foreach (var p in parts)
        {
            string clean = p.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? p.Substring(2) : p;
            if (byte.TryParse(clean, System.Globalization.NumberStyles.HexNumber, null, out byte b))
            {
                list.Add(b);
            }
        }
        return list.ToArray();
    }

    private void Apply()
    {
        var bytes = ParseBytes(_txtHex.Text);
        if (_chkPadNops.IsChecked == true && bytes.Length < _origByteCount)
        {
            int diff = _origByteCount - bytes.Length;
            var padded = new List<byte>(bytes);
            padded.AddRange(Enumerable.Repeat((byte)0x90, diff));
            bytes = padded.ToArray();
        }

        if (bytes.Length == 0)
        {
            MessageBox.Show("Please enter valid assembly instruction or hex bytes.", "Patch Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ResultBytes = bytes;
        DialogResult = true;
        Close();
    }
}

public class ByteEditDialog : Window
{
    private TextBox _txtBytes;
    public byte[] ResultBytes { get; private set; } = Array.Empty<byte>();

    public ByteEditDialog(string address, string hex0_3, string hex4_7, string hex8_B, string hexC_F)
    {
        Title = $"Edit Hex Bytes @ 0x{address}";
        Width = 540;
        Height = 280;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        ResizeMode = ResizeMode.NoResize;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var mainPanel = new StackPanel { Margin = new Thickness(16) };

        var lblPrompt = new TextBlock
        {
            Text = $"Edit 16-Byte Row at 0x{address}:",
            FontWeight = FontWeights.SemiBold,
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 8)
        };
        mainPanel.Children.Add(lblPrompt);

        string fullHex = $"{hex0_3} {hex4_7} {hex8_B} {hexC_F}".Trim();
        _txtBytes = new TextBox
        {
            Text = fullHex,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 13,
            Padding = new Thickness(8, 6, 8, 6),
            Margin = new Thickness(0, 0, 0, 16),
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1))
        };
        mainPanel.Children.Add(_txtBytes);

        var quickPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 16) };
        var btnNop = new Button { Content = "Fill 16x NOP (90)", Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 6, 0) };
        btnNop.Click += (s, e) => _txtBytes.Text = string.Join(" ", System.Linq.Enumerable.Repeat("90", 16));
        quickPanel.Children.Add(btnNop);

        var btnZero = new Button { Content = "Zero Out (00)", Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 6, 0) };
        btnZero.Click += (s, e) => _txtBytes.Text = string.Join(" ", System.Linq.Enumerable.Repeat("00", 16));
        quickPanel.Children.Add(btnZero);

        mainPanel.Children.Add(quickPanel);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnOk = new Button
        {
            Content = "Write Bytes (Enter)",
            Width = 140,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnOk.Click += (s, e) => Confirm();
        btnPanel.Children.Add(btnOk);

        var btnCancel = new Button
        {
            Content = "Cancel",
            Width = 80,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        mainPanel.Children.Add(btnPanel);
        Content = mainPanel;

        KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) Confirm();
            else if (e.Key == Key.Escape) { DialogResult = false; Close(); }
        };

        Loaded += (s, e) => { _txtBytes.Focus(); _txtBytes.SelectAll(); };
    }

    private void Confirm()
    {
        var parts = _txtBytes.Text.Split(new[] { ' ', ',', '-', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        var list = new List<byte>();
        foreach (var p in parts)
        {
            if (byte.TryParse(p, System.Globalization.NumberStyles.HexNumber, null, out byte b))
            {
                list.Add(b);
            }
        }
        if (list.Count == 0)
        {
            MessageBox.Show("Please enter valid hex bytes.", "Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        ResultBytes = list.ToArray();
        DialogResult = true;
        Close();
    }
}

public class StructureEditorDialog : Window
{
    private TextBox _txtName;
    private ListView _lvFields;
    private TextBox _txtCodePreview;
    private TextBlock _lblTotalSize;

    public CustomStructModel StructModel { get; private set; }

    public StructureEditorDialog(CustomStructModel? existing = null)
    {
        StructModel = existing ?? new CustomStructModel { Name = "CUSTOM_STRUCT" };
        if (StructModel.Fields.Count == 0)
        {
            StructModel.Fields.Add(new StructFieldModel { Offset = 0x00, Name = "field_00", TypeName = "uint32", Size = 4, Comment = "ID / Flags" });
            StructModel.Fields.Add(new StructFieldModel { Offset = 0x04, Name = "field_04", TypeName = "int32", Size = 4, Comment = "Value / Status" });
            StructModel.Fields.Add(new StructFieldModel { Offset = 0x08, Name = "field_08", TypeName = "pointer", Size = 8, Comment = "Next node pointer" });
        }

        Title = $"Data Type Manager - Structure Editor [{StructModel.Name}]";
        Width = 740;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Header & Name
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1.4, GridUnitType.Star) }); // Fields
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // C Code Preview
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Footer buttons

        // 1. Top Section
        var topPanel = new StackPanel { Margin = new Thickness(14, 12, 14, 8) };
        var namePanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
        namePanel.Children.Add(new TextBlock { Text = "Structure Name:", FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) });
        _txtName = new TextBox { Text = StructModel.Name, Width = 260, FontFamily = new FontFamily("Consolas"), Padding = new Thickness(6, 4, 6, 4) };
        _txtName.TextChanged += (s, e) =>
        {
            StructModel.Name = _txtName.Text.Trim();
            UpdateCodePreview();
        };
        namePanel.Children.Add(_txtName);

        _lblTotalSize = new TextBlock
        {
            Text = $"Total Size: {StructModel.TotalSize} bytes (0x{StructModel.TotalSize:X2})",
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(20, 0, 0, 0)
        };
        namePanel.Children.Add(_lblTotalSize);
        topPanel.Children.Add(namePanel);

        // Toolbar
        var toolPanel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 4) };
        var btnAdd = new Button { Content = "➕ Add Field", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 6, 0), Background = new SolidColorBrush(Color.FromRgb(0xDC, 0xFC, 0xE7)), Foreground = new SolidColorBrush(Color.FromRgb(0x16, 0x65, 0x34)), FontWeight = FontWeights.SemiBold };
        btnAdd.Click += (s, e) => AddField();
        toolPanel.Children.Add(btnAdd);

        var btnRemove = new Button { Content = "➖ Remove Field", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 6, 0), Background = new SolidColorBrush(Color.FromRgb(0xFE, 0xE2, 0xE2)), Foreground = new SolidColorBrush(Color.FromRgb(0x99, 0x1B, 0x1B)) };
        btnRemove.Click += (s, e) => RemoveField();
        toolPanel.Children.Add(btnRemove);

        var btnAlign = new Button { Content = "📐 Auto Align (4-Byte)", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 6, 0) };
        btnAlign.Click += (s, e) => AutoAlign(4);
        toolPanel.Children.Add(btnAlign);

        var btnAlign8 = new Button { Content = "📐 Auto Align (8-Byte)", Padding = new Thickness(10, 4, 10, 4) };
        btnAlign8.Click += (s, e) => AutoAlign(8);
        toolPanel.Children.Add(btnAlign8);

        topPanel.Children.Add(toolPanel);
        Grid.SetRow(topPanel, 0);
        grid.Children.Add(topPanel);

        // 2. Fields ListView
        _lvFields = new ListView
        {
            ItemsSource = StructModel.Fields,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Margin = new Thickness(14, 0, 14, 6),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1))
        };
        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "Offset", Width = 80, DisplayMemberBinding = new System.Windows.Data.Binding("OffsetHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Field Name", Width = 150, DisplayMemberBinding = new System.Windows.Data.Binding("Name") });
        gv.Columns.Add(new GridViewColumn { Header = "Data Type", Width = 120, DisplayMemberBinding = new System.Windows.Data.Binding("TypeName") });
        gv.Columns.Add(new GridViewColumn { Header = "Size (Bytes)", Width = 90, DisplayMemberBinding = new System.Windows.Data.Binding("Size") });
        gv.Columns.Add(new GridViewColumn { Header = "Comment", Width = 220, DisplayMemberBinding = new System.Windows.Data.Binding("Comment") });
        _lvFields.View = gv;
        Grid.SetRow(_lvFields, 1);
        grid.Children.Add(_lvFields);

        // 3. C Header Code Preview
        var previewBorder = new Border
        {
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            BorderThickness = new Thickness(1),
            Margin = new Thickness(14, 4, 14, 8)
        };
        _txtCodePreview = new TextBox
        {
            IsReadOnly = true,
            Background = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x38, 0xBD, 0xF8)),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Padding = new Thickness(8),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto
        };
        previewBorder.Child = _txtCodePreview;
        Grid.SetRow(previewBorder, 2);
        grid.Children.Add(previewBorder);

        // 4. Footer Buttons
        var footer = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(12)
        };
        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

        var btnSave = new Button
        {
            Content = "💾 Save to Data Types (Enter)",
            Width = 200,
            Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnSave.Click += (s, e) => Save();
        btnPanel.Children.Add(btnSave);

        var btnClose = new Button
        {
            Content = "Cancel",
            Width = 90,
            Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55))
        };
        btnClose.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnClose);

        footer.Child = btnPanel;
        Grid.SetRow(footer, 3);
        grid.Children.Add(footer);

        Content = grid;
        UpdateCodePreview();
    }

    private void AddField()
    {
        int nextOffset = StructModel.Fields.Count > 0 ? StructModel.Fields.Max(f => f.Offset + f.Size) : 0;
        var f = new StructFieldModel
        {
            Offset = nextOffset,
            Name = $"field_{nextOffset:X2}",
            TypeName = "int32",
            Size = 4,
            Comment = "User defined field"
        };
        StructModel.Fields.Add(f);
        UpdateCodePreview();
    }

    private void RemoveField()
    {
        if (_lvFields.SelectedItem is StructFieldModel f)
        {
            StructModel.Fields.Remove(f);
            UpdateCodePreview();
        }
    }

    private void AutoAlign(int alignment)
    {
        int curOffset = 0;
        foreach (var f in StructModel.Fields)
        {
            int rem = curOffset % alignment;
            if (rem != 0) curOffset += (alignment - rem);
            f.Offset = curOffset;
            curOffset += f.Size;
        }
        UpdateCodePreview();
    }

    private void UpdateCodePreview()
    {
        _txtCodePreview.Text = StructModel.GenerateCHeader();
        _lblTotalSize.Text = $"Total Size: {StructModel.TotalSize} bytes (0x{StructModel.TotalSize:X2})";
    }

    private void Save()
    {
        if (string.IsNullOrWhiteSpace(_txtName.Text))
        {
            MessageBox.Show("Please specify a valid structure name.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        StructModel.Name = _txtName.Text.Trim();
        DialogResult = true;
        Close();
    }
}

public class ApplyDataTypeDialog : Window
{
    private ComboBox _cmbTypes;
    private CheckBox _chkPointer;
    public string SelectedTypeName { get; private set; } = string.Empty;

    public ApplyDataTypeDialog(ulong address, ProgramModel model)
    {
        Title = $"Apply Data Type @ 0x{address:X8}";
        Width = 440;
        Height = 250;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        ResizeMode = ResizeMode.NoResize;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var mainPanel = new StackPanel { Margin = new Thickness(16) };

        var lblPrompt = new TextBlock
        {
            Text = $"Select Data Type to apply to address 0x{address:X8}:",
            FontWeight = FontWeights.SemiBold,
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 10)
        };
        mainPanel.Children.Add(lblPrompt);

        _cmbTypes = new ComboBox
        {
            Padding = new Thickness(8, 6, 8, 6),
            FontSize = 13,
            FontFamily = new FontFamily("Consolas"),
            Margin = new Thickness(0, 0, 0, 12)
        };

        // Add user custom structures first
        foreach (var cs in model.CustomStructures)
        {
            _cmbTypes.Items.Add($"struct {cs.Name}");
        }

        // Add Windows structs
        _cmbTypes.Items.Add("IMAGE_DOS_HEADER");
        _cmbTypes.Items.Add("IMAGE_FILE_HEADER");
        _cmbTypes.Items.Add("IMAGE_OPTIONAL_HEADER");
        _cmbTypes.Items.Add("IMAGE_SECTION_HEADER");
        _cmbTypes.Items.Add("PEB");
        _cmbTypes.Items.Add("TEB");

        // Add built-ins
        _cmbTypes.Items.Add("int32");
        _cmbTypes.Items.Add("uint32");
        _cmbTypes.Items.Add("int64");
        _cmbTypes.Items.Add("uint64");
        _cmbTypes.Items.Add("char*");
        _cmbTypes.Items.Add("void*");
        _cmbTypes.Items.Add("float");
        _cmbTypes.Items.Add("double");

        _cmbTypes.SelectedIndex = 0;
        mainPanel.Children.Add(_cmbTypes);

        _chkPointer = new CheckBox
        {
            Content = "Apply as Pointer type (*)",
            IsChecked = true,
            FontWeight = FontWeights.Medium,
            Margin = new Thickness(0, 0, 0, 16)
        };
        mainPanel.Children.Add(_chkPointer);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnOk = new Button
        {
            Content = "Apply Type (Enter)",
            Width = 130,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnOk.Click += (s, e) => Confirm();
        btnPanel.Children.Add(btnOk);

        var btnCancel = new Button
        {
            Content = "Cancel",
            Width = 80,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        mainPanel.Children.Add(btnPanel);
        Content = mainPanel;

        KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) Confirm();
            else if (e.Key == Key.Escape) { DialogResult = false; Close(); }
        };
    }

    private void Confirm()
    {
        string raw = _cmbTypes.SelectedItem?.ToString() ?? "int32";
        if (raw.StartsWith("struct ")) raw = raw.Substring(7);
        SelectedTypeName = (_chkPointer.IsChecked == true) ? $"{raw}*" : raw;
        DialogResult = true;
        Close();
    }
}

public class BookmarkDialog : Window
{
    private TextBox _txtNote;
    private ComboBox _cmbCategory;
    public string Category => _cmbCategory.SelectedItem?.ToString() ?? "Note";
    public string Description => _txtNote.Text.Trim();
    public bool DeleteRequested { get; private set; }

    public BookmarkDialog(ulong address, string currentCategory = "Note", string currentNote = "", bool isExisting = false)
    {
        Title = isExisting ? $"Edit Bookmark (0x{address:X8})" : $"Add Bookmark (0x{address:X8})";
        Width = 440;
        Height = 260;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = new SolidColorBrush(Color.FromRgb(0xFA, 0xFA, 0xFA));

        var mainPanel = new StackPanel { Margin = new Thickness(16) };

        var lblCat = new TextBlock { Text = "Bookmark Category:", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblCat);

        _cmbCategory = new ComboBox { Margin = new Thickness(0, 0, 0, 12), Padding = new Thickness(4) };
        _cmbCategory.Items.Add("Note");
        _cmbCategory.Items.Add("Info");
        _cmbCategory.Items.Add("Warning");
        _cmbCategory.Items.Add("Error");
        _cmbCategory.SelectedItem = currentCategory;
        mainPanel.Children.Add(_cmbCategory);

        var lblNote = new TextBlock { Text = "Description / Annotation:", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblNote);

        _txtNote = new TextBox
        {
            Text = currentNote,
            Height = 50,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 16),
            Padding = new Thickness(6)
        };
        mainPanel.Children.Add(_txtNote);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };

        if (isExisting)
        {
            var btnDelete = new Button
            {
                Content = "🗑️ Delete",
                Width = 80,
                Height = 30,
                Background = new SolidColorBrush(Color.FromRgb(0xFE, 0xE2, 0xE2)),
                Foreground = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26)),
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 0, 12, 0)
            };
            btnDelete.Click += (s, e) => { DeleteRequested = true; DialogResult = true; Close(); };
            btnPanel.Children.Add(btnDelete);
        }

        var btnOk = new Button
        {
            Content = "Save Bookmark",
            Width = 110,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnOk.Click += (s, e) => { DialogResult = true; Close(); };
        btnPanel.Children.Add(btnOk);

        var btnCancel = new Button
        {
            Content = "Cancel",
            Width = 70,
            Height = 30,
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        mainPanel.Children.Add(btnPanel);
        Content = mainPanel;
    }
}

public class EnumEditorDialog : Window
{
    private TextBox _txtName;
    private ComboBox _cmbUnderlyingType;
    private ListView _lvMembers;
    private TextBox _txtPreview;
    private CustomEnumModel _enumModel;

    public CustomEnumModel ResultEnum => _enumModel;

    public EnumEditorDialog(CustomEnumModel? existing = null)
    {
        Title = (existing == null) ? "Ghidra.NET - Create New Enum" : $"Ghidra.NET - Edit Enum [{existing.Name}]";
        Width = 720;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));

        _enumModel = existing != null ? new CustomEnumModel
        {
            Name = existing.Name,
            UnderlyingType = existing.UnderlyingType,
            Members = new ObservableCollection<EnumMemberModel>(existing.Members.Select(m => new EnumMemberModel { Name = m.Name, Value = m.Value, Comment = m.Comment }))
        } : new CustomEnumModel
        {
            Name = "STATUS_CODE",
            UnderlyingType = "uint32"
        };

        if (_enumModel.Members.Count == 0)
        {
            _enumModel.Members.Add(new EnumMemberModel { Name = "STATUS_SUCCESS", Value = 0, Comment = "Operation succeeded" });
            _enumModel.Members.Add(new EnumMemberModel { Name = "STATUS_PENDING", Value = 0x103, Comment = "Asynchronous operation pending" });
            _enumModel.Members.Add(new EnumMemberModel { Name = "STATUS_ACCESS_DENIED", Value = 0x5, Comment = "Access denied" });
        }

        var grid = new Grid { Margin = new Thickness(14) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Header
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Name & Type
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Members ListView
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Buttons
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(120) }); // C Header Preview
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Actions

        // 1. Header
        var tbHeader = new TextBlock
        {
            Text = "🏷️ Enum Definition Editor",
            FontSize = 16,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A)),
            Margin = new Thickness(0, 0, 0, 10)
        };
        Grid.SetRow(tbHeader, 0);
        grid.Children.Add(tbHeader);

        // 2. Name & Type
        var spTop = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 10) };
        spTop.Children.Add(new TextBlock { Text = "Enum Name:", VerticalAlignment = VerticalAlignment.Center, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 8, 0) });
        _txtName = new TextBox { Text = _enumModel.Name, Width = 200, Padding = new Thickness(4) };
        _txtName.TextChanged += (s, e) => { _enumModel.Name = _txtName.Text.Trim(); UpdatePreview(); };
        spTop.Children.Add(_txtName);

        spTop.Children.Add(new TextBlock { Text = "Underlying Type:", VerticalAlignment = VerticalAlignment.Center, FontWeight = FontWeights.SemiBold, Margin = new Thickness(20, 0, 8, 0) });
        _cmbUnderlyingType = new ComboBox { Width = 120, Padding = new Thickness(4) };
        _cmbUnderlyingType.Items.Add("uint32");
        _cmbUnderlyingType.Items.Add("int32");
        _cmbUnderlyingType.Items.Add("uint16");
        _cmbUnderlyingType.Items.Add("int16");
        _cmbUnderlyingType.Items.Add("uint8");
        _cmbUnderlyingType.Items.Add("int8");
        _cmbUnderlyingType.Items.Add("uint64");
        _cmbUnderlyingType.SelectedItem = _enumModel.UnderlyingType;
        _cmbUnderlyingType.SelectionChanged += (s, e) => { _enumModel.UnderlyingType = _cmbUnderlyingType.SelectedItem?.ToString() ?? "uint32"; UpdatePreview(); };
        spTop.Children.Add(_cmbUnderlyingType);

        Grid.SetRow(spTop, 1);
        grid.Children.Add(spTop);

        // 3. Members ListView
        _lvMembers = new ListView
        {
            ItemsSource = _enumModel.Members,
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1))
        };
        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "Member Name", Width = 220, DisplayMemberBinding = new System.Windows.Data.Binding("Name") });
        gv.Columns.Add(new GridViewColumn { Header = "Hex Value", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding("ValueHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Dec Value", Width = 90, DisplayMemberBinding = new System.Windows.Data.Binding("Value") });
        gv.Columns.Add(new GridViewColumn { Header = "Comment", Width = 230, DisplayMemberBinding = new System.Windows.Data.Binding("Comment") });
        _lvMembers.View = gv;

        Grid.SetRow(_lvMembers, 2);
        grid.Children.Add(_lvMembers);

        // 4. Buttons
        var spBtns = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 8) };
        var btnAdd = new Button { Content = "➕ Add Member", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 8, 0) };
        btnAdd.Click += (s, e) =>
        {
            long nextVal = _enumModel.Members.Count > 0 ? _enumModel.Members.Max(m => m.Value) + 1 : 0;
            _enumModel.Members.Add(new EnumMemberModel { Name = $"MEMBER_{_enumModel.Members.Count}", Value = nextVal });
            UpdatePreview();
        };
        spBtns.Children.Add(btnAdd);

        var btnRemove = new Button { Content = "➖ Remove Selected", Padding = new Thickness(10, 4, 10, 4) };
        btnRemove.Click += (s, e) =>
        {
            if (_lvMembers.SelectedItem is EnumMemberModel sel)
            {
                _enumModel.Members.Remove(sel);
                UpdatePreview();
            }
        };
        spBtns.Children.Add(btnRemove);

        Grid.SetRow(spBtns, 3);
        grid.Children.Add(spBtns);

        // 5. C Header Preview
        _txtPreview = new TextBox
        {
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            IsReadOnly = true,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Padding = new Thickness(8),
            Margin = new Thickness(0, 0, 0, 10)
        };
        Grid.SetRow(_txtPreview, 4);
        grid.Children.Add(_txtPreview);

        // 6. Action buttons
        var spActions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnSave = new Button
        {
            Content = "Save Enum",
            Width = 100,
            Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnSave.Click += (s, e) => { DialogResult = true; Close(); };
        spActions.Children.Add(btnSave);

        var btnCancel = new Button { Content = "Cancel", Width = 80, Height = 32 };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        spActions.Children.Add(btnCancel);

        Grid.SetRow(spActions, 5);
        grid.Children.Add(spActions);

        Content = grid;
        UpdatePreview();
    }

    private void UpdatePreview()
    {
        _txtPreview.Text = _enumModel.GenerateCHeader();
    }
}

public class SearchSuiteDialog : Window
{
    private TextBox _txtQuery;
    private ListView _lvResults;
    private ProgramModel _programModel;
    public ulong? SelectedAddress { get; private set; }

    public SearchSuiteDialog(ProgramModel model)
    {
        _programModel = model;
        Title = "Ghidra.NET - Global Search Suite (Strings, Hex Bytes, Scalars)";
        Width = 840;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));

        var grid = new Grid { Margin = new Thickness(14) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Header & Controls
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Results Grid
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Bottom Status & Jump

        // 1. Controls
        var topPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
        var tbTitle = new TextBlock
        {
            Text = "🔎 Global Memory & Binary Search",
            FontSize = 16,
            FontWeight = FontWeights.Bold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A)),
            Margin = new Thickness(0, 0, 0, 8)
        };
        topPanel.Children.Add(tbTitle);

        var spSearch = new StackPanel { Orientation = Orientation.Horizontal };
        _txtQuery = new TextBox { Width = 360, Padding = new Thickness(6, 4, 6, 4), FontFamily = new FontFamily("Consolas") };
        _txtQuery.KeyDown += (s, e) => { if (e.Key == Key.Enter) RunStringSearch(); };
        spSearch.Children.Add(_txtQuery);

        var btnStr = new Button { Content = "🔤 Search Strings", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(8, 0, 4, 0) };
        btnStr.Click += (s, e) => RunStringSearch();
        spSearch.Children.Add(btnStr);

        var btnHex = new Button { Content = "🔍 Search Hex Bytes", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(4, 0, 4, 0) };
        btnHex.Click += (s, e) => RunHexSearch();
        spSearch.Children.Add(btnHex);

        var btnScalar = new Button { Content = "🔢 Search Scalar", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(4, 0, 0, 0) };
        btnScalar.Click += (s, e) => RunScalarSearch();
        spSearch.Children.Add(btnScalar);

        topPanel.Children.Add(spSearch);
        Grid.SetRow(topPanel, 0);
        grid.Children.Add(topPanel);

        // 2. Results ListView
        _lvResults = new ListView
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1))
        };
        _lvResults.MouseDoubleClick += (s, e) => ConfirmJump();
        _lvResults.KeyDown += (s, e) => { if (e.Key == Key.Enter) ConfirmJump(); };

        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "Type", Width = 50, DisplayMemberBinding = new System.Windows.Data.Binding("TypeIcon") });
        gv.Columns.Add(new GridViewColumn { Header = "Address", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding("AddressHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Section", Width = 70, DisplayMemberBinding = new System.Windows.Data.Binding("SectionName") });
        gv.Columns.Add(new GridViewColumn { Header = "Preview / Match", Width = 380, DisplayMemberBinding = new System.Windows.Data.Binding("Preview") });
        gv.Columns.Add(new GridViewColumn { Header = "Detail", Width = 180, DisplayMemberBinding = new System.Windows.Data.Binding("Detail") });
        _lvResults.View = gv;

        Grid.SetRow(_lvResults, 1);
        grid.Children.Add(_lvResults);

        // 3. Bottom Jump Button
        var botPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
        var btnJump = new Button
        {
            Content = "Jump to Location (Enter)",
            Padding = new Thickness(14, 6, 14, 6),
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold
        };
        btnJump.Click += (s, e) => ConfirmJump();
        botPanel.Children.Add(btnJump);

        Grid.SetRow(botPanel, 2);
        grid.Children.Add(botPanel);

        Content = grid;
        Loaded += (s, e) =>
        {
            _txtQuery.Focus();
            RunStringSearch(); // default populate with extracted strings
        };
    }

    private void RunStringSearch()
    {
        var res = SearchService.SearchStrings(_programModel, _txtQuery.Text);
        _lvResults.ItemsSource = res;
    }

    private void RunHexSearch()
    {
        var res = SearchService.SearchHexBytes(_programModel, _txtQuery.Text);
        _lvResults.ItemsSource = res;
    }

    private void RunScalarSearch()
    {
        var res = SearchService.SearchScalars(_programModel, _txtQuery.Text);
        _lvResults.ItemsSource = res;
    }

    private void ConfirmJump()
    {
        if (_lvResults.SelectedItem is SearchResultItem item)
        {
            SelectedAddress = item.Address;
            DialogResult = true;
            Close();
        }
    }
}

// =========================================================================
// Tier 1 Enhancements Dialogs: SetEquate, MemoryMap, FunctionComparison
// =========================================================================

public class SetEquateDialog : Window
{
    public string SelectedEquateName { get; private set; } = string.Empty;
    public string SelectedCategory { get; private set; } = "Custom";
    public ulong TargetValue { get; private set; }

    private TextBox _txtName;
    private TextBox _txtCategory;
    private ListView _lvMatches;

    public SetEquateDialog(ulong address, string instruction, string operands, ulong value)
    {
        TargetValue = value;
        Title = $"Set Equate (Constant Symbol) @ 0x{address:X8}";
        Width = 560;
        Height = 460;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        ResizeMode = ResizeMode.NoResize;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var mainPanel = new StackPanel { Margin = new Thickness(16) };

        var infoBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xEE, 0xF2, 0xF6)),
            CornerRadius = new CornerRadius(4),
            Padding = new Thickness(10),
            Margin = new Thickness(0, 0, 0, 10)
        };
        var infoText = new TextBlock
        {
            Text = $"Address: 0x{address:X8}\nInstruction: {instruction} {operands}\nTarget Immediate Value: 0x{value:X} ({value})",
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Foreground = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55))
        };
        infoBorder.Child = infoText;
        mainPanel.Children.Add(infoBorder);

        var lblMatches = new TextBlock { Text = "Known Constant Candidates:", FontWeight = FontWeights.SemiBold, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblMatches);

        _lvMatches = new ListView { Height = 140, Margin = new Thickness(0, 0, 0, 10), FontFamily = new FontFamily("Consolas"), FontSize = 12 };
        var gridView = new GridView();
        gridView.Columns.Add(new GridViewColumn { Header = "Constant Name", Width = 220, DisplayMemberBinding = new System.Windows.Data.Binding("Name") });
        gridView.Columns.Add(new GridViewColumn { Header = "Category", Width = 90, DisplayMemberBinding = new System.Windows.Data.Binding("Category") });
        gridView.Columns.Add(new GridViewColumn { Header = "Description", Width = 200, DisplayMemberBinding = new System.Windows.Data.Binding("Desc") });
        _lvMatches.View = gridView;

        var matches = EquateService.FindMatches(value);
        _lvMatches.ItemsSource = matches;
        _lvMatches.SelectionChanged += (s, e) =>
        {
            if (_lvMatches.SelectedItem is ValueTuple<string, ulong, string, string> item)
            {
                _txtName.Text = item.Item1;
                _txtCategory.Text = item.Item3;
            }
        };
        mainPanel.Children.Add(_lvMatches);

        var lblCustom = new TextBlock { Text = "Equate Name:", FontWeight = FontWeights.SemiBold, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblCustom);

        _txtName = new TextBox
        {
            Text = matches.Count > 0 ? matches[0].Name : $"CONST_0x{value:X}",
            FontFamily = new FontFamily("Consolas"),
            FontSize = 13,
            Padding = new Thickness(6, 4, 6, 4),
            Margin = new Thickness(0, 0, 0, 8)
        };
        mainPanel.Children.Add(_txtName);

        var lblCat = new TextBlock { Text = "Category:", FontWeight = FontWeights.SemiBold, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) };
        mainPanel.Children.Add(lblCat);

        _txtCategory = new TextBox
        {
            Text = matches.Count > 0 ? matches[0].Category : "Custom",
            Padding = new Thickness(6, 4, 6, 4),
            Margin = new Thickness(0, 0, 0, 14)
        };
        mainPanel.Children.Add(_txtCategory);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnApply = new Button
        {
            Content = "Apply Equate (Enter)",
            Width = 140,
            Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnApply.Click += (s, e) => Apply();
        btnPanel.Children.Add(btnApply);

        var btnCancel = new Button
        {
            Content = "Cancel (Esc)",
            Width = 90,
            Height = 32,
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        mainPanel.Children.Add(btnPanel);
        Content = mainPanel;

        KeyDown += (s, e) =>
        {
            if (e.Key == Key.Enter) Apply();
            else if (e.Key == Key.Escape) { DialogResult = false; Close(); }
        };
    }

    private void Apply()
    {
        string name = _txtName.Text.Trim();
        if (string.IsNullOrEmpty(name))
        {
            MessageBox.Show("Please enter a valid equate name.", "Equate Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        SelectedEquateName = name;
        SelectedCategory = _txtCategory.Text.Trim();
        DialogResult = true;
        Close();
    }
}

public class MemoryMapWindow : Window
{
    private ProgramModel _programModel;
    private Action<string> _jumpCallback;
    private Action<string>? _logCallback;
    private ListView _lvSections;

    public MemoryMapWindow(ProgramModel model, Action<string> jumpCallback, Action<string>? logCallback = null)
    {
        _programModel = model;
        _jumpCallback = jumpCallback;
        _logCallback = logCallback;

        Title = $"Memory Map - {_programModel.ProgramName} (Base: 0x{_programModel.ImageBase:X8})";
        Width = 840;
        Height = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Toolbar
        var tbBorder = new Border { Background = Brushes.White, BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)), BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(8, 6, 8, 6) };
        var tb = new StackPanel { Orientation = Orientation.Horizontal };

        var btnAdd = new Button { Content = "➕ Add Block", Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(2, 0, 2, 0), Background = new SolidColorBrush(Color.FromRgb(0xDC, 0xFC, 0xE7)), Foreground = new SolidColorBrush(Color.FromRgb(0x16, 0x65, 0x34)), FontWeight = FontWeights.SemiBold };
        btnAdd.Click += (s, e) => AddBlock_Click();
        tb.Children.Add(btnAdd);

        var btnSplit = new Button { Content = "✂️ Split Block", Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(2, 0, 2, 0), Background = new SolidColorBrush(Color.FromRgb(0xFE, 0xF9, 0xC3)), Foreground = new SolidColorBrush(Color.FromRgb(0x85, 0x4D, 0x0E)), FontWeight = FontWeights.SemiBold };
        btnSplit.Click += (s, e) => SplitBlock_Click();
        tb.Children.Add(btnSplit);

        var btnRebase = new Button { Content = "🔄 Rebase Program", Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(2, 0, 2, 0), Background = new SolidColorBrush(Color.FromRgb(0xEE, 0xF2, 0xFF)), Foreground = new SolidColorBrush(Color.FromRgb(0x37, 0x30, 0xA3)), FontWeight = FontWeights.SemiBold };
        btnRebase.Click += (s, e) => Rebase_Click();
        tb.Children.Add(btnRebase);

        var btnDelete = new Button { Content = "🗑️ Delete Block", Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(2, 0, 2, 0), Background = new SolidColorBrush(Color.FromRgb(0xFE, 0xE2, 0xE2)), Foreground = new SolidColorBrush(Color.FromRgb(0x99, 0x1B, 0x1B)), FontWeight = FontWeights.SemiBold };
        btnDelete.Click += (s, e) => DeleteBlock_Click();
        tb.Children.Add(btnDelete);

        var btnJump = new Button { Content = "🔍 Jump to Block", Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(10, 0, 2, 0), Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)) };
        btnJump.Click += (s, e) => JumpSelected();
        tb.Children.Add(btnJump);

        tbBorder.Child = tb;
        Grid.SetRow(tbBorder, 0);
        grid.Children.Add(tbBorder);

        // Sections ListView
        _lvSections = new ListView { BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"), FontSize = 12 };
        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "Name", Width = 90, DisplayMemberBinding = new System.Windows.Data.Binding("Name") });
        gv.Columns.Add(new GridViewColumn { Header = "Start Address", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding("StartAddressHex") });
        gv.Columns.Add(new GridViewColumn { Header = "End Address", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding("EndAddressHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Length", Width = 80, DisplayMemberBinding = new System.Windows.Data.Binding("SizeHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Perms", Width = 60, DisplayMemberBinding = new System.Windows.Data.Binding("Permissions") });
        gv.Columns.Add(new GridViewColumn { Header = "Type", Width = 90, DisplayMemberBinding = new System.Windows.Data.Binding("BlockType") });
        gv.Columns.Add(new GridViewColumn { Header = "Comment", Width = 260, DisplayMemberBinding = new System.Windows.Data.Binding("Comment") });
        _lvSections.View = gv;
        _lvSections.ItemsSource = _programModel.Sections;
        _lvSections.MouseDoubleClick += (s, e) => JumpSelected();

        Grid.SetRow(_lvSections, 1);
        grid.Children.Add(_lvSections);

        // Status bar
        var sb = new Border { Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)), Padding = new Thickness(8, 4, 8, 4) };
        var lblCount = new TextBlock { Text = $"{_programModel.Sections.Count} memory block(s) total. Double-click any row to navigate.", FontSize = 11, Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)) };
        sb.Child = lblCount;
        Grid.SetRow(sb, 2);
        grid.Children.Add(sb);

        Content = grid;
    }

    private void JumpSelected()
    {
        if (_lvSections.SelectedItem is SectionNode sec)
        {
            _jumpCallback(sec.StartAddressHex);
            Close();
        }
    }

    private void AddBlock_Click()
    {
        var dlg = new PromptDialog("Add Memory Block", "Enter Block Name (e.g. .patch):", ".patch");
        if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.InputText))
        {
            string name = dlg.InputText.Trim();
            ulong maxEnd = _programModel.Sections.Count > 0 ? _programModel.Sections.Max(s => s.EndAddress) : _programModel.ImageBase + 0x10000;
            ulong alignEnd = (maxEnd + 0xFFF) & ~0xFFFUL;

            MemoryMapService.AddBlock(_programModel, name, alignEnd, 0x1000, true, true, true, "Initialized", "User Added Virtual Block");
            _logCallback?.Invoke($"[MemoryMap] Created block '{name}' @ 0x{alignEnd:X8} (Size: 0x1000, RWX)");
        }
    }

    private void SplitBlock_Click()
    {
        if (_lvSections.SelectedItem is SectionNode sec)
        {
            ulong mid = sec.StartAddress + (ulong)(sec.Size / 2);
            var dlg = new PromptDialog("Split Memory Block", $"Enter Split Address (between 0x{sec.StartAddress:X8} and 0x{sec.EndAddress:X8}):", $"{mid:X8}");
            if (dlg.ShowDialog() == true && ulong.TryParse(dlg.InputText.Replace("0x", "").Trim(), System.Globalization.NumberStyles.HexNumber, null, out ulong splitAddr))
            {
                if (splitAddr > sec.StartAddress && splitAddr < sec.EndAddress)
                {
                    MemoryMapService.SplitBlock(_programModel, sec, splitAddr, $"{sec.Name}_1");
                    _logCallback?.Invoke($"[MemoryMap] Splitted block '{sec.Name}' at 0x{splitAddr:X8}");
                }
                else
                {
                    MessageBox.Show("Split address must be strictly within section bounds.", "Split Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }
        else
        {
            MessageBox.Show("Please select a memory block to split.", "Selection Required", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void Rebase_Click()
    {
        var dlg = new PromptDialog("Rebase Program", "Enter New Image Base (Hex):", $"{_programModel.ImageBase:X8}");
        if (dlg.ShowDialog() == true && ulong.TryParse(dlg.InputText.Replace("0x", "").Trim(), System.Globalization.NumberStyles.HexNumber, null, out ulong newBase))
        {
            MemoryMapService.RebaseProgram(_programModel, newBase, _logCallback);
            Title = $"Memory Map - {_programModel.ProgramName} (Base: 0x{_programModel.ImageBase:X8})";
            MessageBox.Show($"Program successfully rebased to 0x{newBase:X8}.", "Rebase Succeeded", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void DeleteBlock_Click()
    {
        if (_lvSections.SelectedItem is SectionNode sec)
        {
            if (MessageBox.Show($"Are you sure you want to remove section '{sec.Name}' @ 0x{sec.StartAddress:X8}?", "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                MemoryMapService.DeleteBlock(_programModel, sec);
                _logCallback?.Invoke($"[MemoryMap] Deleted block '{sec.Name}' @ 0x{sec.StartAddress:X8}");
            }
        }
    }
}

public class FunctionComparisonWindow : Window
{
    private ProgramModel _programModel;
    private Action<string> _jumpCallback;
    private ComboBox _cmbFuncA;
    private ComboBox _cmbFuncB;
    private ListView _lvLeft;
    private ListView _lvRight;
    private TextBlock _lblDiffSummary;
    private RadioButton _rbDisasm;
    private RadioButton _rbDecomp;
    private CheckBox _chkSyncScroll;
    private bool _syncing;

    public FunctionComparisonWindow(ProgramModel model, Action<string> jumpCallback, string? initialFuncA = null, string? initialFuncB = null)
    {
        _programModel = model;
        _jumpCallback = jumpCallback;

        Title = "Function Comparison (Side-by-Side Dual Pane) - CodeBrowser";
        Width = 960;
        Height = 600;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Toolbar
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // Split View
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // Status

        // Toolbar
        var tbBorder = new Border { Background = Brushes.White, BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)), BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(10, 8, 10, 8) };
        var tb = new StackPanel { Orientation = Orientation.Horizontal };

        tb.Children.Add(new TextBlock { Text = "Function A:", FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) });
        _cmbFuncA = new ComboBox { Width = 160, Margin = new Thickness(0, 0, 12, 0) };
        tb.Children.Add(_cmbFuncA);

        tb.Children.Add(new TextBlock { Text = "Function B:", FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) });
        _cmbFuncB = new ComboBox { Width = 160, Margin = new Thickness(0, 0, 14, 0) };
        tb.Children.Add(_cmbFuncB);

        _rbDisasm = new RadioButton { Content = "📜 Disassembly Diff", IsChecked = true, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
        _rbDisasm.Checked += (s, e) => RunDiff();
        tb.Children.Add(_rbDisasm);

        _rbDecomp = new RadioButton { Content = "⚡ Decompiler C Diff", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) };
        _rbDecomp.Checked += (s, e) => RunDiff();
        tb.Children.Add(_rbDecomp);

        _chkSyncScroll = new CheckBox { Content = "Synchronize Scrolling", IsChecked = true, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(6, 0, 10, 0) };
        tb.Children.Add(_chkSyncScroll);

        var btnRefresh = new Button { Content = "🔄 Compare", Padding = new Thickness(10, 3, 10, 3), Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)), Foreground = Brushes.White, FontWeight = FontWeights.SemiBold };
        btnRefresh.Click += (s, e) => RunDiff();
        tb.Children.Add(btnRefresh);

        tbBorder.Child = tb;
        Grid.SetRow(tbBorder, 0);
        grid.Children.Add(tbBorder);

        // Center Dual Panes
        var centerGrid = new Grid();
        centerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        centerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
        centerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        _lvLeft = CreateDiffListView();
        _lvLeft.MouseDoubleClick += (s, e) =>
        {
            if (_lvLeft.SelectedItem is DiffLineModel item && !string.IsNullOrEmpty(item.AddressHex))
            {
                _jumpCallback(item.AddressHex);
            }
        };
        Grid.SetColumn(_lvLeft, 0);
        centerGrid.Children.Add(_lvLeft);

        var splitter = new GridSplitter { HorizontalAlignment = HorizontalAlignment.Stretch, Background = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)) };
        Grid.SetColumn(splitter, 1);
        centerGrid.Children.Add(splitter);

        _lvRight = CreateDiffListView();
        _lvRight.MouseDoubleClick += (s, e) =>
        {
            if (_lvRight.SelectedItem is DiffLineModel item && !string.IsNullOrEmpty(item.AddressHex))
            {
                _jumpCallback(item.AddressHex);
            }
        };
        Grid.SetColumn(_lvRight, 2);
        centerGrid.Children.Add(_lvRight);

        // Synchronize scroll
        _lvLeft.SelectionChanged += (s, e) =>
        {
            if (_chkSyncScroll.IsChecked == true && !_syncing)
            {
                _syncing = true;
                _lvRight.SelectedIndex = _lvLeft.SelectedIndex;
                if (_lvRight.SelectedItem != null) _lvRight.ScrollIntoView(_lvRight.SelectedItem);
                _syncing = false;
            }
        };
        _lvRight.SelectionChanged += (s, e) =>
        {
            if (_chkSyncScroll.IsChecked == true && !_syncing)
            {
                _syncing = true;
                _lvLeft.SelectedIndex = _lvRight.SelectedIndex;
                if (_lvLeft.SelectedItem != null) _lvLeft.ScrollIntoView(_lvLeft.SelectedItem);
                _syncing = false;
            }
        };

        Grid.SetRow(centerGrid, 1);
        grid.Children.Add(centerGrid);

        // Bottom status
        var sb = new Border { Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)), Padding = new Thickness(8, 4, 8, 4) };
        _lblDiffSummary = new TextBlock { Text = "Ready to compare. Select two functions above and click Compare.", FontSize = 11, Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69)) };
        sb.Child = _lblDiffSummary;
        Grid.SetRow(sb, 2);
        grid.Children.Add(sb);

        Content = grid;

        // Populate functions
        PopulateFunctions(initialFuncA, initialFuncB);
    }

    private ListView CreateDiffListView()
    {
        var lv = new ListView
        {
            BorderThickness = new Thickness(0),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12
        };

        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "#", Width = 35, DisplayMemberBinding = new System.Windows.Data.Binding("LineNumber") });
        gv.Columns.Add(new GridViewColumn { Header = "Tag", Width = 40, DisplayMemberBinding = new System.Windows.Data.Binding("KindTag") });
        gv.Columns.Add(new GridViewColumn { Header = "Address", Width = 95, DisplayMemberBinding = new System.Windows.Data.Binding("AddressHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Code / Instruction", Width = 300, DisplayMemberBinding = new System.Windows.Data.Binding("Text") });
        lv.View = gv;

        return lv;
    }

    private void PopulateFunctions(string? initialA, string? initialB)
    {
        var funcs = _programModel.ListingLines
            .Where(l => l.IsFunctionHeader && !string.IsNullOrEmpty(l.FunctionName))
            .Select(l => l.FunctionName)
            .Distinct()
            .ToList();

        if (funcs.Count == 0) funcs.Add("main");

        _cmbFuncA.ItemsSource = funcs;
        _cmbFuncB.ItemsSource = funcs;

        _cmbFuncA.SelectedItem = initialA ?? funcs.FirstOrDefault();
        _cmbFuncB.SelectedItem = initialB ?? (funcs.Count > 1 ? funcs[1] : funcs[0]);

        _cmbFuncA.SelectionChanged += (s, e) => RunDiff();
        _cmbFuncB.SelectionChanged += (s, e) => RunDiff();

        RunDiff();
    }

    private void RunDiff()
    {
        string? funcA = _cmbFuncA.SelectedItem as string;
        string? funcB = _cmbFuncB.SelectedItem as string;
        if (string.IsNullOrEmpty(funcA) || string.IsNullOrEmpty(funcB)) return;

        ulong addrA = GetFuncAddr(funcA);
        ulong addrB = GetFuncAddr(funcB);

        if (_rbDisasm.IsChecked == true)
        {
            var linesA = CallTreeService.GetFunctionInstructions(_programModel, addrA, funcA);
            var linesB = CallTreeService.GetFunctionInstructions(_programModel, addrB, funcB);

            var (left, right, diffs) = FunctionDiffService.CompareDisassembly(linesA, linesB);
            _lvLeft.ItemsSource = left;
            _lvRight.ItemsSource = right;
            _lblDiffSummary.Text = $"Disassembly Diff: {funcA} ({linesA.Count} insts) vs {funcB} ({linesB.Count} insts) | {diffs} difference(s) detected.";
        }
        else
        {
            string codeA = DecompilerPipeService.DecompileFunction(_programModel, funcA, $"{addrA:X8}");
            string codeB = DecompilerPipeService.DecompileFunction(_programModel, funcB, $"{addrB:X8}");

            var (left, right, diffs) = FunctionDiffService.ComparePseudocode(codeA, codeB);
            _lvLeft.ItemsSource = left;
            _lvRight.ItemsSource = right;
            _lblDiffSummary.Text = $"Decompiled C Diff: {funcA} vs {funcB} | {diffs} difference(s) detected.";
        }
    }

    private ulong GetFuncAddr(string funcName)
    {
        var line = _programModel.ListingLines.FirstOrDefault(l => l.IsFunctionHeader && l.FunctionName.Equals(funcName, StringComparison.OrdinalIgnoreCase));
        if (line != null && ulong.TryParse(line.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            return addr;
        return _programModel.EntryPoint;
    }
}

// =========================================================================
// Tier 2 Windows & Dialogs: CParserDialog, EntropyWindow, PdbSymbolWindow,
// ModifyFallthroughDialog, ScriptManagerWindow
// =========================================================================

public class CParserDialog : Window
{
    private ProgramModel _programModel;
    private Action<string>? _logCallback;
    private TextBox _txtCode;
    private ComboBox _cmbPresets;
    private ListView _lvResults;
    private TextBlock _lblStatus;
    private CParseResult? _lastResult;

    public CParserDialog(ProgramModel programModel, Action<string>? logCallback = null)
    {
        _programModel = programModel;
        _logCallback = logCallback;

        Title = "Parse C Source / Header (.h) - GhidraNet";
        Width = 860;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // 1. Toolbar
        var tbBorder = new Border
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            Padding = new Thickness(10, 8, 10, 8)
        };
        var tb = new StackPanel { Orientation = Orientation.Horizontal };
        tb.Children.Add(new TextBlock { Text = "Header Preset:", VerticalAlignment = VerticalAlignment.Center, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 8, 0) });

        _cmbPresets = new ComboBox { Width = 280, Margin = new Thickness(0, 0, 10, 0) };
        _cmbPresets.Items.Add("Windows NT Internals (PEB & TEB & UNICODE_STRING)");
        _cmbPresets.Items.Add("Winsock Network API (sockaddr_in & in_addr)");
        _cmbPresets.Items.Add("Cryptographic Structs (AES_KEY & SHA256_CTX)");
        _cmbPresets.Items.Add("C Standard Data Structs (LinkedList & TreeNode)");
        _cmbPresets.SelectedIndex = 0;
        _cmbPresets.SelectionChanged += (s, e) => LoadPreset();
        tb.Children.Add(_cmbPresets);

        var btnLoadPreset = new Button { Content = "📥 Insert Preset", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 8, 0) };
        btnLoadPreset.Click += (s, e) => LoadPreset();
        tb.Children.Add(btnLoadPreset);

        var btnOpenFile = new Button { Content = "📂 Open .h File...", Padding = new Thickness(10, 4, 10, 4) };
        btnOpenFile.Click += (s, e) => OpenHeaderFile();
        tb.Children.Add(btnOpenFile);

        tbBorder.Child = tb;
        Grid.SetRow(tbBorder, 0);
        root.Children.Add(tbBorder);

        // 2. Center Splitter
        var centerGrid = new Grid();
        centerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });
        centerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
        centerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });

        _txtCode = new TextBox
        {
            AcceptsReturn = true,
            AcceptsTab = true,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0)
        };
        Grid.SetColumn(_txtCode, 0);
        centerGrid.Children.Add(_txtCode);

        var splitter = new GridSplitter { HorizontalAlignment = HorizontalAlignment.Stretch, Background = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)) };
        Grid.SetColumn(splitter, 1);
        centerGrid.Children.Add(splitter);

        var rightPanel = new DockPanel { Background = Brushes.White };
        var rightHeader = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            Padding = new Thickness(8, 6, 8, 6),
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1))
        };
        rightHeader.Child = new TextBlock { Text = "📋 Parsed Types Preview", FontWeight = FontWeights.SemiBold, FontSize = 12 };
        DockPanel.SetDock(rightHeader, Dock.Top);
        rightPanel.Children.Add(rightHeader);

        _lvResults = new ListView { BorderThickness = new Thickness(0), FontFamily = new FontFamily("Segoe UI"), FontSize = 12 };
        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "Type Name", Width = 130, DisplayMemberBinding = new System.Windows.Data.Binding("Name") });
        gv.Columns.Add(new GridViewColumn { Header = "Kind", Width = 60, DisplayMemberBinding = new System.Windows.Data.Binding("Kind") });
        gv.Columns.Add(new GridViewColumn { Header = "Size / Info", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding("Info") });
        _lvResults.View = gv;
        rightPanel.Children.Add(_lvResults);

        Grid.SetColumn(rightPanel, 2);
        centerGrid.Children.Add(rightPanel);

        Grid.SetRow(centerGrid, 1);
        root.Children.Add(centerGrid);

        // 3. Bottom Bar
        var bottomBorder = new Border
        {
            Background = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Padding = new Thickness(10, 8, 10, 8)
        };
        var bottomDock = new DockPanel();

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnPreview = new Button { Content = "🔍 Parse & Preview", Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(0, 0, 8, 0) };
        btnPreview.Click += (s, e) => ParseCurrentCode();
        btnPanel.Children.Add(btnPreview);

        var btnImport = new Button
        {
            Content = "📥 Import to Data Type Manager",
            Padding = new Thickness(12, 5, 12, 5),
            Background = new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold
        };
        btnImport.Click += (s, e) => ImportToProgram();
        btnPanel.Children.Add(btnImport);

        var btnClose = new Button { Content = "Close", Padding = new Thickness(12, 5, 12, 5), Margin = new Thickness(8, 0, 0, 0) };
        btnClose.Click += (s, e) => Close();
        btnPanel.Children.Add(btnClose);

        DockPanel.SetDock(btnPanel, Dock.Right);
        bottomDock.Children.Add(btnPanel);

        _lblStatus = new TextBlock
        {
            Text = "Paste or edit C header declarations and click 'Parse & Preview'.",
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)),
            FontSize = 11
        };
        bottomDock.Children.Add(_lblStatus);

        bottomBorder.Child = bottomDock;
        Grid.SetRow(bottomBorder, 2);
        root.Children.Add(bottomBorder);

        Content = root;
        LoadPreset();
    }

    private void LoadPreset()
    {
        switch (_cmbPresets.SelectedIndex)
        {
            case 0:
                _txtCode.Text = @"// Windows NT PEB / TEB Internals
typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
    unsigned int Length;
    unsigned char Initialized;
    void* SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    unsigned char InheritedAddressSpace;
    unsigned char ReadImageFileExecOptions;
    unsigned char BeingDebugged;
    unsigned char BitField;
    void* Mutant;
    void* ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    void* ProcessParameters;
    unsigned int SessionId;
} PEB, *PPEB;
";
                break;
            case 1:
                _txtCode.Text = @"// Winsock Network Structures
typedef unsigned int SOCKET;

typedef enum _SOCKET_AF {
    AF_UNSPEC = 0,
    AF_INET = 2,
    AF_IPX = 6,
    AF_APPLETALK = 16,
    AF_NETBIOS = 17,
    AF_INET6 = 23
} SOCKET_AF;

typedef struct _in_addr {
    union {
        struct { unsigned char s_b1, s_b2, s_b3, s_b4; } S_un_b;
        unsigned int S_addr;
    } S_un;
} in_addr;

typedef struct _sockaddr_in {
    short sin_family;
    unsigned short sin_port;
    in_addr sin_addr;
    char sin_zero[8];
} sockaddr_in;

typedef struct _SOCKET_SESSION {
    SOCKET SocketHandle;
    sockaddr_in ClientAddr;
    unsigned int BytesSent;
    unsigned int BytesReceived;
} SOCKET_SESSION;
";
                break;
            case 2:
                _txtCode.Text = @"// Cryptographic Structs
typedef enum _CRYPTO_ALGO {
    ALGO_MD5 = 0x8003,
    ALGO_SHA1 = 0x8004,
    ALGO_SHA256 = 0x800C,
    ALGO_AES_128 = 0x660E,
    ALGO_AES_256 = 0x6610
} CRYPTO_ALGO;

typedef struct _AES_KEY {
    unsigned int rd_key[60];
    int rounds;
} AES_KEY;

typedef struct _SHA256_CTX {
    unsigned int state[8];
    unsigned int count[2];
    unsigned char buffer[64];
} SHA256_CTX;
";
                break;
            case 3:
                _txtCode.Text = @"// Standard C Data Structures
typedef struct _ListNode {
    struct _ListNode* Next;
    struct _ListNode* Prev;
    void* Value;
    int Key;
} ListNode;

typedef struct _BinaryTreeNode {
    struct _BinaryTreeNode* Left;
    struct _BinaryTreeNode* Right;
    int Value;
    int Height;
} BinaryTreeNode;
";
                break;
        }
        ParseCurrentCode();
    }

    private void OpenHeaderFile()
    {
        var ofd = new OpenFileDialog
        {
            Filter = "C Header Files (*.h;*.hpp;*.c;*.cpp)|*.h;*.hpp;*.c;*.cpp|All Files (*.*)|*.*",
            Title = "Open C Header File"
        };
        if (ofd.ShowDialog() == true)
        {
            try
            {
                _txtCode.Text = File.ReadAllText(ofd.FileName);
                ParseCurrentCode();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to read file: {ex.Message}", "File Open Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void ParseCurrentCode()
    {
        _lastResult = CParserService.ParseCSource(_txtCode.Text);
        var previewList = new List<dynamic>();

        foreach (var s in _lastResult.Structs)
        {
            previewList.Add(new { Name = s.Name, Kind = "Struct", Info = $"{s.Fields.Count} fields, {s.TotalSize} B" });
        }
        foreach (var e in _lastResult.Enums)
        {
            previewList.Add(new { Name = e.Name, Kind = "Enum", Info = $"{e.Members.Count} members" });
        }
        foreach (var (k, v) in _lastResult.Typedefs)
        {
            previewList.Add(new { Name = k, Kind = "Typedef", Info = $"= {v}" });
        }

        _lvResults.ItemsSource = previewList;
        _lblStatus.Text = $"Parsed {_lastResult.Structs.Count} struct(s), {_lastResult.Enums.Count} enum(s), {_lastResult.Typedefs.Count} typedef(s).";
    }

    private void ImportToProgram()
    {
        if (_lastResult == null || !_lastResult.Success)
        {
            ParseCurrentCode();
        }

        if (_lastResult == null || !_lastResult.Success)
        {
            MessageBox.Show("No valid C data types detected to import. Please check your C header syntax.", "Import Failed", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        CParserService.ApplyToProgram(_programModel, _lastResult);
        _logCallback?.Invoke($"[CParser] Successfully imported {_lastResult.Structs.Count} struct(s) and {_lastResult.Enums.Count} enum(s) into Data Type Manager.");
        MessageBox.Show($"Successfully imported {_lastResult.Structs.Count} struct(s) and {_lastResult.Enums.Count} enum(s) into 'C Header Imports' folder!", "Import Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        DialogResult = true;
        Close();
    }
}

public class EntropyWindow : Window
{
    private ProgramModel _programModel;
    private Action<string> _jumpCallback;
    private ComboBox _cmbBlockSize;
    private ListView _lvSections;
    private ItemsControl _icBars;
    private TextBlock _lblSummary;

    public EntropyWindow(ProgramModel programModel, Action<string> jumpCallback)
    {
        _programModel = programModel;
        _jumpCallback = jumpCallback;

        Title = $"Entropy Overview - {_programModel.ProgramName} (Shannon Entropy 0.0 - 8.0)";
        Width = 920;
        Height = 580;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(140) });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(4) });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

        // Toolbar
        var tbBorder = new Border { Background = Brushes.White, BorderThickness = new Thickness(0, 0, 0, 1), BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)), Padding = new Thickness(10, 8, 10, 8) };
        var tb = new StackPanel { Orientation = Orientation.Horizontal };

        tb.Children.Add(new TextBlock { Text = "Block Size:", FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        _cmbBlockSize = new ComboBox { Width = 110, Margin = new Thickness(0, 0, 12, 0) };
        _cmbBlockSize.Items.Add("256 Bytes");
        _cmbBlockSize.Items.Add("512 Bytes");
        _cmbBlockSize.Items.Add("1024 Bytes");
        _cmbBlockSize.Items.Add("4096 Bytes");
        _cmbBlockSize.SelectedIndex = 2;
        _cmbBlockSize.SelectionChanged += (s, e) => Recalculate();
        tb.Children.Add(_cmbBlockSize);

        var btnRecalc = new Button { Content = "🔄 Recalculate", Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 0, 16, 0) };
        btnRecalc.Click += (s, e) => Recalculate();
        tb.Children.Add(btnRecalc);

        tb.Children.Add(new Border { Background = new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)), Width = 12, Height = 12, CornerRadius = new CornerRadius(2), Margin = new Thickness(0, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center });
        tb.Children.Add(new TextBlock { Text = "Packed/Encrypted (>7.0)", FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) });

        tb.Children.Add(new Border { Background = new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)), Width = 12, Height = 12, CornerRadius = new CornerRadius(2), Margin = new Thickness(0, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center });
        tb.Children.Add(new TextBlock { Text = "Executable Code (5.2-7.0)", FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 12, 0) });

        tb.Children.Add(new Border { Background = new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)), Width = 12, Height = 12, CornerRadius = new CornerRadius(2), Margin = new Thickness(0, 0, 4, 0), VerticalAlignment = VerticalAlignment.Center });
        tb.Children.Add(new TextBlock { Text = "Data/Sparse (<5.2)", FontSize = 11, VerticalAlignment = VerticalAlignment.Center });

        tbBorder.Child = tb;
        Grid.SetRow(tbBorder, 0);
        root.Children.Add(tbBorder);

        // Histogram Graph
        var histContainer = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A)),
            Padding = new Thickness(10, 8, 10, 8),
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x41, 0x55))
        };
        var histScroll = new ScrollViewer { HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled };

        _icBars = new ItemsControl();
        var panelFactory = new FrameworkElementFactory(typeof(StackPanel));
        panelFactory.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal);
        panelFactory.SetValue(StackPanel.VerticalAlignmentProperty, VerticalAlignment.Bottom);
        _icBars.ItemsPanel = new ItemsPanelTemplate(panelFactory);

        var itemTemplate = new DataTemplate();
        var borderFactory = new FrameworkElementFactory(typeof(Border));
        borderFactory.SetBinding(Border.HeightProperty, new System.Windows.Data.Binding("BarHeight"));
        borderFactory.SetValue(Border.WidthProperty, 3.5);
        borderFactory.SetValue(Border.MarginProperty, new Thickness(0, 0, 1, 0));
        borderFactory.SetValue(Border.VerticalAlignmentProperty, VerticalAlignment.Bottom);
        borderFactory.SetBinding(Border.BackgroundProperty, new System.Windows.Data.Binding("RiskColor"));
        borderFactory.SetBinding(ToolTipProperty, new System.Windows.Data.Binding { StringFormat = "{0} @ {1}: Entropy {2:F2} / 8.0" });
        borderFactory.AddHandler(Border.MouseLeftButtonDownEvent, new MouseButtonEventHandler((s, e) =>
        {
            if (s is Border b && b.DataContext is EntropyBlockModel block)
            {
                _jumpCallback(block.AddressHex);
            }
        }));
        itemTemplate.VisualTree = borderFactory;
        _icBars.ItemTemplate = itemTemplate;

        histScroll.Content = _icBars;
        histContainer.Child = histScroll;
        Grid.SetRow(histContainer, 1);
        root.Children.Add(histContainer);

        var splitter = new GridSplitter { HorizontalAlignment = HorizontalAlignment.Stretch, Background = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)) };
        Grid.SetRow(splitter, 2);
        root.Children.Add(splitter);

        // Section table
        var tableDock = new DockPanel { Background = Brushes.White };
        var tableHeader = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            Padding = new Thickness(10, 6, 10, 6)
        };
        _lblSummary = new TextBlock { Text = "Section Entropy Breakdown", FontWeight = FontWeights.SemiBold, FontSize = 12 };
        tableHeader.Child = _lblSummary;
        DockPanel.SetDock(tableHeader, Dock.Top);
        tableDock.Children.Add(tableHeader);

        _lvSections = new ListView { BorderThickness = new Thickness(0), FontFamily = new FontFamily("Consolas"), FontSize = 12 };
        _lvSections.MouseDoubleClick += (s, e) =>
        {
            if (_lvSections.SelectedItem is SectionEntropyModel sec)
            {
                _jumpCallback(sec.StartAddressHex);
            }
        };

        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "Section", Width = 90, DisplayMemberBinding = new System.Windows.Data.Binding("Name") });
        gv.Columns.Add(new GridViewColumn { Header = "Start Address", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding("StartAddressHex") });
        gv.Columns.Add(new GridViewColumn { Header = "End Address", Width = 110, DisplayMemberBinding = new System.Windows.Data.Binding("EndAddressHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Size", Width = 90, DisplayMemberBinding = new System.Windows.Data.Binding("SizeHex") });
        gv.Columns.Add(new GridViewColumn { Header = "Shannon Entropy", Width = 130, DisplayMemberBinding = new System.Windows.Data.Binding("EntropyText") });
        gv.Columns.Add(new GridViewColumn { Header = "Assessment", Width = 200, DisplayMemberBinding = new System.Windows.Data.Binding("Status") });
        _lvSections.View = gv;
        tableDock.Children.Add(_lvSections);

        Grid.SetRow(tableDock, 3);
        root.Children.Add(tableDock);

        Content = root;
        Recalculate();
    }

    private void Recalculate()
    {
        int blockSize = _cmbBlockSize.SelectedIndex switch
        {
            0 => 256,
            1 => 512,
            2 => 1024,
            3 => 4096,
            _ => 1024
        };

        var secEntropies = EntropyService.AnalyzeSections(_programModel);
        _programModel.SectionEntropies.Clear();
        foreach (var s in secEntropies) _programModel.SectionEntropies.Add(s);
        _lvSections.ItemsSource = _programModel.SectionEntropies;

        var blocks = EntropyService.AnalyzeBlocks(_programModel, blockSize);
        _programModel.EntropyBlocks.Clear();
        foreach (var b in blocks) _programModel.EntropyBlocks.Add(b);
        _icBars.ItemsSource = _programModel.EntropyBlocks;

        int highRisk = secEntropies.Count(s => s.Entropy >= 7.0);
        _lblSummary.Text = $"Section Entropy Breakdown | {secEntropies.Count} section(s) analyzed, {blocks.Count} blocks mapped. {(highRisk > 0 ? $"⚠️ {highRisk} packed section(s) detected!" : "✅ Binary appears unpacked.")}";
    }
}

public class PdbSymbolWindow : Window
{
    private ProgramModel _programModel;
    private Action<string> _jumpCallback;
    private Action<string>? _logCallback;

    private TextBox _txtPdbPath;
    private TextBox _txtPdbGuid;
    private TextBox _txtPdbAge;
    private TextBox _txtSymbolUrl;
    private TextBlock _lblPdbStatus;

    private TextBox _txtMangledInput;
    private TextBox _txtDemangledOutput;
    private ComboBox _cmbMangledPresets;

    public PdbSymbolWindow(ProgramModel programModel, Action<string> jumpCallback, Action<string>? logCallback = null)
    {
        _programModel = programModel;
        _jumpCallback = jumpCallback;
        _logCallback = logCallback;

        Title = $"PDB & Symbol Server / Demangler - {_programModel.ProgramName}";
        Width = 780;
        Height = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var root = new Grid();
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Group 1: PDB & Symbol Server
        var gbPdb = new GroupBox
        {
            Header = "🛡️ CodeView RSDS & Microsoft Symbol Server",
            Margin = new Thickness(10, 8, 10, 4),
            FontWeight = FontWeights.SemiBold
        };
        var pdbGrid = new Grid { Margin = new Thickness(10) };
        pdbGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        pdbGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        pdbGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        pdbGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        pdbGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        pdbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
        pdbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        pdbGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        pdbGrid.Children.Add(new TextBlock { Text = "PDB File / Path:", FontWeight = FontWeights.Normal, VerticalAlignment = VerticalAlignment.Center });
        _txtPdbPath = new TextBox { IsReadOnly = true, Margin = new Thickness(4, 2, 4, 2), VerticalAlignment = VerticalAlignment.Center, FontFamily = new FontFamily("Consolas") };
        Grid.SetColumn(_txtPdbPath, 1);
        pdbGrid.Children.Add(_txtPdbPath);

        var btnScanPdb = new Button { Content = "🔍 Re-Scan RSDS", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(4, 2, 0, 2) };
        btnScanPdb.Click += (s, e) => ScanPdbInfo();
        Grid.SetColumn(btnScanPdb, 2);
        pdbGrid.Children.Add(btnScanPdb);

        var row1Label = new TextBlock { Text = "GUID & Age:", FontWeight = FontWeights.Normal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
        Grid.SetRow(row1Label, 1);
        pdbGrid.Children.Add(row1Label);

        var spGuidAge = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(4, 4, 4, 2) };
        _txtPdbGuid = new TextBox { Width = 300, IsReadOnly = true, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 0, 10, 0) };
        spGuidAge.Children.Add(_txtPdbGuid);
        spGuidAge.Children.Add(new TextBlock { Text = "Age:", FontWeight = FontWeights.Normal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
        _txtPdbAge = new TextBox { Width = 70, IsReadOnly = true, FontFamily = new FontFamily("Consolas") };
        spGuidAge.Children.Add(_txtPdbAge);

        Grid.SetRow(spGuidAge, 1);
        Grid.SetColumn(spGuidAge, 1);
        Grid.SetColumnSpan(spGuidAge, 2);
        pdbGrid.Children.Add(spGuidAge);

        var row2Label = new TextBlock { Text = "Symbol Server URL:", FontWeight = FontWeights.Normal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
        Grid.SetRow(row2Label, 2);
        pdbGrid.Children.Add(row2Label);

        _txtSymbolUrl = new TextBox { IsReadOnly = true, Margin = new Thickness(4, 4, 4, 2), VerticalAlignment = VerticalAlignment.Center, FontFamily = new FontFamily("Consolas") };
        Grid.SetRow(_txtSymbolUrl, 2);
        Grid.SetColumn(_txtSymbolUrl, 1);
        pdbGrid.Children.Add(_txtSymbolUrl);

        var btnCopyUrl = new Button { Content = "📋 Copy URL", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(4, 4, 0, 2) };
        btnCopyUrl.Click += (s, e) =>
        {
            if (!string.IsNullOrEmpty(_txtSymbolUrl.Text))
            {
                Clipboard.SetText(_txtSymbolUrl.Text);
                MessageBox.Show("Symbol Server URL copied to clipboard!", "Copied", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        };
        Grid.SetRow(btnCopyUrl, 2);
        Grid.SetColumn(btnCopyUrl, 2);
        pdbGrid.Children.Add(btnCopyUrl);

        _lblPdbStatus = new TextBlock { Text = "Status: Ready", FontWeight = FontWeights.Normal, Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69)), Margin = new Thickness(4, 6, 4, 2), FontSize = 11 };
        Grid.SetRow(_lblPdbStatus, 3);
        Grid.SetColumn(_lblPdbStatus, 1);
        Grid.SetColumnSpan(_lblPdbStatus, 2);
        pdbGrid.Children.Add(_lblPdbStatus);

        gbPdb.Content = pdbGrid;
        Grid.SetRow(gbPdb, 0);
        root.Children.Add(gbPdb);

        // Group 2: C++ Symbol Demangler
        var gbDemangle = new GroupBox
        {
            Header = "🔤 C++ Symbol Demangler (MSVC & GCC / Itanium ABI)",
            Margin = new Thickness(10, 4, 10, 8),
            FontWeight = FontWeights.SemiBold
        };
        var dmGrid = new Grid { Margin = new Thickness(10) };
        dmGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        dmGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        dmGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        dmGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        dmGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(140) });
        dmGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        dmGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        dmGrid.Children.Add(new TextBlock { Text = "Sample Presets:", FontWeight = FontWeights.Normal, VerticalAlignment = VerticalAlignment.Center });
        _cmbMangledPresets = new ComboBox { Margin = new Thickness(4, 2, 4, 2) };
        _cmbMangledPresets.Items.Add("?Add@Calculator@@QEAAHHH@Z (MSVC Method)");
        _cmbMangledPresets.Items.Add("??0MyString@@QEAA@PEBD@Z (MSVC Constructor)");
        _cmbMangledPresets.Items.Add("??1MyString@@UEAA@XZ (MSVC Destructor)");
        _cmbMangledPresets.Items.Add("??_7Widget@@6B@ (MSVC VTable)");
        _cmbMangledPresets.Items.Add("_ZN7MyClass3fooEi (GCC/Itanium Method)");
        _cmbMangledPresets.Items.Add("_ZN7MyClassC1Ev (GCC Constructor)");
        _cmbMangledPresets.Items.Add("_ZTV7MyClass (GCC VTable)");
        _cmbMangledPresets.SelectedIndex = 0;
        _cmbMangledPresets.SelectionChanged += (s, e) => LoadMangledPreset();
        Grid.SetColumn(_cmbMangledPresets, 1);
        dmGrid.Children.Add(_cmbMangledPresets);

        var row1DmLabel = new TextBlock { Text = "Mangled Symbol:", FontWeight = FontWeights.Normal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
        Grid.SetRow(row1DmLabel, 1);
        dmGrid.Children.Add(row1DmLabel);

        _txtMangledInput = new TextBox { Margin = new Thickness(4, 4, 4, 2), VerticalAlignment = VerticalAlignment.Center, FontFamily = new FontFamily("Consolas") };
        _txtMangledInput.TextChanged += (s, e) => LiveDemangle();
        Grid.SetRow(_txtMangledInput, 1);
        Grid.SetColumn(_txtMangledInput, 1);
        dmGrid.Children.Add(_txtMangledInput);

        var btnDemangleAll = new Button
        {
            Content = "⚡ Demangle All Symbols",
            Padding = new Thickness(8, 3, 8, 3),
            Margin = new Thickness(4, 4, 0, 2),
            Background = new SolidColorBrush(Color.FromRgb(0x43, 0x38, 0xCA)),
            Foreground = Brushes.White
        };
        btnDemangleAll.Click += (s, e) => DemangleAll();
        Grid.SetRow(btnDemangleAll, 1);
        Grid.SetColumn(btnDemangleAll, 2);
        dmGrid.Children.Add(btnDemangleAll);

        var row2DmLabel = new TextBlock { Text = "Demangled C++:", FontWeight = FontWeights.Normal, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
        Grid.SetRow(row2DmLabel, 2);
        dmGrid.Children.Add(row2DmLabel);

        _txtDemangledOutput = new TextBox
        {
            IsReadOnly = true,
            Margin = new Thickness(4, 4, 4, 2),
            VerticalAlignment = VerticalAlignment.Center,
            FontFamily = new FontFamily("Consolas"),
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0x04, 0x78, 0x57))
        };
        Grid.SetRow(_txtDemangledOutput, 2);
        Grid.SetColumn(_txtDemangledOutput, 1);
        Grid.SetColumnSpan(_txtDemangledOutput, 2);
        dmGrid.Children.Add(_txtDemangledOutput);

        gbDemangle.Content = dmGrid;
        Grid.SetRow(gbDemangle, 1);
        root.Children.Add(gbDemangle);

        var btnClose = new Button { Content = "Close", Width = 90, Padding = new Thickness(0, 5, 0, 5), HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 0, 10, 10) };
        btnClose.Click += (s, e) => Close();
        Grid.SetRow(btnClose, 2);
        root.Children.Add(btnClose);

        Content = root;

        ScanPdbInfo();
        LoadMangledPreset();
    }

    private void ScanPdbInfo()
    {
        var pdb = PdbService.ExtractPdbInfo(_programModel.FilePath);
        _programModel.PdbInfo = pdb;

        _txtPdbPath.Text = pdb.PdbPath;
        _txtPdbGuid.Text = pdb.Guid != Guid.Empty ? pdb.Guid.ToString() : "N/A";
        _txtPdbAge.Text = pdb.Age != 0 ? pdb.Age.ToString() : "N/A";
        _txtSymbolUrl.Text = pdb.HasCodeView ? pdb.SymbolServerUrl : "N/A";
        _lblPdbStatus.Text = $"Status: {pdb.Status}";
    }

    private void LoadMangledPreset()
    {
        string? sel = _cmbMangledPresets.SelectedItem as string;
        if (sel != null)
        {
            int space = sel.IndexOf(' ');
            string symbol = space > 0 ? sel.Substring(0, space) : sel;
            _txtMangledInput.Text = symbol;
        }
    }

    private void LiveDemangle()
    {
        string input = _txtMangledInput.Text.Trim();
        if (string.IsNullOrEmpty(input))
        {
            _txtDemangledOutput.Text = "";
            return;
        }

        string demangled = DemanglerService.Demangle(input);
        _txtDemangledOutput.Text = demangled;
    }

    private void DemangleAll()
    {
        int count = DemanglerService.DemangleAllProgramSymbols(_programModel);
        _logCallback?.Invoke($"[Demangler] Scanned and demangled {count} symbol(s) in program.");
        MessageBox.Show($"Scanned program listing and demangled {count} C++ decorated symbol(s)!", "Demangler Complete", MessageBoxButton.OK, MessageBoxImage.Information);
    }
}

public class ModifyFallthroughDialog : Window
{
    private RadioButton _rbDefault;
    private RadioButton _rbCustom;
    private RadioButton _rbNone;
    private TextBox _txtCustomAddress;
    private ulong _defaultNext;

    public ulong? SelectedOverride { get; private set; }

    public ModifyFallthroughDialog(ulong currentAddr, string instruction, string operands, ulong defaultNext, ulong? currentOverride)
    {
        _defaultNext = defaultNext;
        SelectedOverride = currentOverride;

        Title = "Modify Fallthrough Address - GhidraNet";
        Width = 440;
        Height = 260;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        var root = new StackPanel { Margin = new Thickness(16) };

        var lblHeader = new TextBlock
        {
            Text = $"Instruction @ 0x{currentAddr:X8}:",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 4)
        };
        root.Children.Add(lblHeader);

        var txtInst = new TextBox
        {
            Text = $"{instruction} {operands}",
            IsReadOnly = true,
            FontFamily = new FontFamily("Consolas"),
            Padding = new Thickness(4),
            Margin = new Thickness(0, 0, 0, 14)
        };
        root.Children.Add(txtInst);

        _rbDefault = new RadioButton
        {
            Content = $"Default Fallthrough: 0x{defaultNext:X8}",
            IsChecked = !currentOverride.HasValue && currentOverride == null,
            Margin = new Thickness(0, 0, 0, 8)
        };
        root.Children.Add(_rbDefault);

        var spCustom = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
        _rbCustom = new RadioButton
        {
            Content = "Override Fallthrough (Hex):",
            IsChecked = currentOverride.HasValue,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0)
        };
        spCustom.Children.Add(_rbCustom);

        _txtCustomAddress = new TextBox
        {
            Width = 120,
            FontFamily = new FontFamily("Consolas"),
            Text = currentOverride.HasValue ? $"0x{currentOverride.Value:X8}" : $"0x{defaultNext:X8}"
        };
        spCustom.Children.Add(_txtCustomAddress);
        root.Children.Add(spCustom);

        _rbNone = new RadioButton
        {
            Content = "No Fallthrough (Stop linear execution flow)",
            IsChecked = false,
            Margin = new Thickness(0, 0, 0, 16)
        };
        root.Children.Add(_rbNone);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnOk = new Button { Content = "OK", Width = 75, Padding = new Thickness(0, 4, 0, 4), Margin = new Thickness(0, 0, 8, 0), IsDefault = true };
        btnOk.Click += (s, e) => Apply();
        btnPanel.Children.Add(btnOk);

        var btnCancel = new Button { Content = "Cancel", Width = 75, Padding = new Thickness(0, 4, 0, 4), IsCancel = true };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        root.Children.Add(btnPanel);
        Content = root;
    }

    private void Apply()
    {
        if (_rbDefault.IsChecked == true)
        {
            SelectedOverride = _defaultNext;
        }
        else if (_rbNone.IsChecked == true)
        {
            SelectedOverride = null;
        }
        else if (_rbCustom.IsChecked == true)
        {
            string hex = _txtCustomAddress.Text.Replace("0x", "").Trim();
            if (ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out ulong target))
            {
                SelectedOverride = target;
            }
            else
            {
                MessageBox.Show("Please enter a valid hexadecimal target address.", "Invalid Address", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        DialogResult = true;
        Close();
    }
}

public class ScriptManagerWindow : Window
{
    private ProgramModel _programModel;
    private Action<string> _jumpCallback;
    private Action<string>? _logCallback;
    private ulong _currentAddress;
    private string _currentFunctionName;

    private ListView _lvScripts;
    private TextBox _txtEditor;
    private TextBox _txtConsole;
    private TextBox _txtRepl;
    private TextBlock _lblScriptName;
    private ObservableCollection<ScriptItemModel> _scriptList;

    public ScriptManagerWindow(ProgramModel programModel, Action<string> jumpCallback, Action<string>? logCallback, ulong currentAddress, string currentFunctionName)
    {
        _programModel = programModel;
        _jumpCallback = jumpCallback;
        _logCallback = logCallback;
        _currentAddress = currentAddress;
        _currentFunctionName = currentFunctionName;

        Title = "Script Manager & Roslyn C# Console - GhidraNet";
        Width = 980;
        Height = 640;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
        FontFamily = new FontFamily("Segoe UI");

        _scriptList = new ObservableCollection<ScriptItemModel>(RoslynScriptService.GetDefaultScripts());
        foreach (var s in _programModel.Scripts)
        {
            _scriptList.Add(s);
        }

        var root = new Grid();
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(280) });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        // Left Pane: Script list & categories
        var leftDock = new DockPanel { Background = Brushes.White };
        var leftHeader = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9)),
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            Padding = new Thickness(8, 8, 8, 8)
        };
        leftHeader.Child = new TextBlock { Text = "📜 GhidraNet C# Scripts", FontWeight = FontWeights.SemiBold, FontSize = 12 };
        DockPanel.SetDock(leftHeader, Dock.Top);
        leftDock.Children.Add(leftHeader);

        var leftButtons = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC)),
            BorderThickness = new Thickness(0, 1, 0, 0),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            Padding = new Thickness(6)
        };
        var spLeftBtns = new StackPanel { Orientation = Orientation.Horizontal };
        var btnNew = new Button { Content = "➕ New", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(0, 0, 4, 0) };
        btnNew.Click += (s, e) => CreateNewScript();
        spLeftBtns.Children.Add(btnNew);

        var btnSave = new Button { Content = "💾 Save", Padding = new Thickness(8, 2, 8, 2), Margin = new Thickness(0, 0, 4, 0) };
        btnSave.Click += (s, e) => SaveScript();
        spLeftBtns.Children.Add(btnSave);

        var btnDel = new Button { Content = "🗑️ Delete", Padding = new Thickness(8, 2, 8, 2) };
        btnDel.Click += (s, e) => DeleteScript();
        spLeftBtns.Children.Add(btnDel);

        leftButtons.Child = spLeftBtns;
        DockPanel.SetDock(leftButtons, Dock.Bottom);
        leftDock.Children.Add(leftButtons);

        _lvScripts = new ListView { BorderThickness = new Thickness(0), ItemsSource = _scriptList, FontFamily = new FontFamily("Segoe UI"), FontSize = 12 };
        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "Icon", Width = 35, DisplayMemberBinding = new System.Windows.Data.Binding("Icon") });
        gv.Columns.Add(new GridViewColumn { Header = "Script Name", Width = 150, DisplayMemberBinding = new System.Windows.Data.Binding("Name") });
        gv.Columns.Add(new GridViewColumn { Header = "Category", Width = 80, DisplayMemberBinding = new System.Windows.Data.Binding("Category") });
        _lvScripts.View = gv;
        _lvScripts.SelectionChanged += (s, e) => OnScriptSelected();
        leftDock.Children.Add(_lvScripts);

        Grid.SetColumn(leftDock, 0);
        root.Children.Add(leftDock);

        var splitterH = new GridSplitter { HorizontalAlignment = HorizontalAlignment.Stretch, Background = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)) };
        Grid.SetColumn(splitterH, 1);
        root.Children.Add(splitterH);

        // Right Pane: Editor & Output Console
        var rightGrid = new Grid();
        rightGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        rightGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(3, GridUnitType.Star) });
        rightGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(4) });
        rightGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(2, GridUnitType.Star) });
        rightGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Toolbar
        var rightTbBorder = new Border
        {
            Background = Brushes.White,
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            Padding = new Thickness(10, 8, 10, 8)
        };
        var rightTb = new DockPanel();

        var spActions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnRun = new Button
        {
            Content = "▶ Run Script (F5)",
            Padding = new Thickness(12, 4, 12, 4),
            Background = new SolidColorBrush(Color.FromRgb(0x16, 0xA3, 0x4A)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.Bold,
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnRun.Click += async (s, e) => await ExecuteCurrentScriptAsync();
        spActions.Children.Add(btnRun);

        var btnClear = new Button { Content = "Clear Console", Padding = new Thickness(10, 4, 10, 4) };
        btnClear.Click += (s, e) => _txtConsole.Clear();
        spActions.Children.Add(btnClear);

        DockPanel.SetDock(spActions, Dock.Right);
        rightTb.Children.Add(spActions);

        _lblScriptName = new TextBlock { Text = "No script selected", FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, FontSize = 12 };
        rightTb.Children.Add(_lblScriptName);

        rightTbBorder.Child = rightTb;
        Grid.SetRow(rightTbBorder, 0);
        rightGrid.Children.Add(rightTbBorder);

        // Editor
        _txtEditor = new TextBox
        {
            AcceptsReturn = true,
            AcceptsTab = true,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 13,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(8)
        };
        Grid.SetRow(_txtEditor, 1);
        rightGrid.Children.Add(_txtEditor);

        var splitterV = new GridSplitter { HorizontalAlignment = HorizontalAlignment.Stretch, Background = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)) };
        Grid.SetRow(splitterV, 2);
        rightGrid.Children.Add(splitterV);

        // Console
        _txtConsole = new TextBox
        {
            IsReadOnly = true,
            Background = new SolidColorBrush(Color.FromRgb(0x1E, 0x1E, 0x1E)),
            Foreground = new SolidColorBrush(Color.FromRgb(0xD4, 0xD4, 0xD4)),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(8)
        };
        Grid.SetRow(_txtConsole, 3);
        rightGrid.Children.Add(_txtConsole);

        // Interactive REPL bar
        var replBorder = new Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x2D, 0x2D, 0x2D)),
            Padding = new Thickness(8, 4, 8, 4)
        };
        var replDock = new DockPanel();

        var btnReplRun = new Button
        {
            Content = "Execute",
            Padding = new Thickness(10, 2, 10, 2),
            Background = new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)),
            Foreground = Brushes.White,
            FontWeight = FontWeights.SemiBold
        };
        btnReplRun.Click += async (s, e) => await ExecuteReplAsync();
        DockPanel.SetDock(btnReplRun, Dock.Right);
        replDock.Children.Add(btnReplRun);

        var lblPrompt = new TextBlock
        {
            Text = "C# > ",
            FontFamily = new FontFamily("Consolas"),
            Foreground = new SolidColorBrush(Color.FromRgb(0x10, 0xB9, 0x81)),
            FontWeight = FontWeights.Bold,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 4, 0)
        };
        DockPanel.SetDock(lblPrompt, Dock.Left);
        replDock.Children.Add(lblPrompt);

        _txtRepl = new TextBox
        {
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Background = new SolidColorBrush(Color.FromRgb(0x1E, 0x1E, 0x1E)),
            Foreground = Brushes.White,
            BorderThickness = new Thickness(0),
            Margin = new Thickness(4, 0, 8, 0)
        };
        _txtRepl.KeyDown += async (s, e) =>
        {
            if (e.Key == Key.Enter)
            {
                await ExecuteReplAsync();
            }
        };
        replDock.Children.Add(_txtRepl);

        replBorder.Child = replDock;
        Grid.SetRow(replBorder, 4);
        rightGrid.Children.Add(replBorder);

        Grid.SetColumn(rightGrid, 2);
        root.Children.Add(rightGrid);

        Content = root;

        if (_scriptList.Count > 0)
        {
            _lvScripts.SelectedIndex = 0;
        }

        KeyDown += async (s, e) =>
        {
            if (e.Key == Key.F5)
            {
                await ExecuteCurrentScriptAsync();
            }
        };
    }

    private void OnScriptSelected()
    {
        if (_lvScripts.SelectedItem is ScriptItemModel s)
        {
            _lblScriptName.Text = $"{s.Icon} {s.Name} ({s.Category}) - {s.Description}";
            _txtEditor.Text = s.ScriptCode;
        }
    }

    private void CreateNewScript()
    {
        var item = new ScriptItemModel
        {
            Name = $"CustomScript_{_scriptList.Count + 1}",
            Category = "User",
            Description = "User created custom reverse engineering script.",
            Icon = "⚡",
            ScriptCode = @"// C# Ghidra Script
Print($""Executing on program: {CurrentProgram.ProgramName}"");
Print($""Current address: 0x{CurrentAddress:X8}"");
Print($""Listing items: {Listing.Count}"");
"
        };
        _scriptList.Add(item);
        _lvScripts.SelectedItem = item;
    }

    private void SaveScript()
    {
        if (_lvScripts.SelectedItem is ScriptItemModel s)
        {
            s.ScriptCode = _txtEditor.Text;
            MessageBox.Show($"Script '{s.Name}' saved successfully.", "Saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void DeleteScript()
    {
        if (_lvScripts.SelectedItem is ScriptItemModel s)
        {
            if (MessageBox.Show($"Are you sure you want to delete '{s.Name}'?", "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
            {
                _scriptList.Remove(s);
            }
        }
    }

    private async Task ExecuteCurrentScriptAsync()
    {
        string code = _txtEditor.Text;
        if (string.IsNullOrWhiteSpace(code)) return;

        _txtConsole.AppendText($"\n--- Running Script at {DateTime.Now:HH:mm:ss} ---\n");

        var globals = CreateScriptGlobals();
        var (success, output, result) = await RoslynScriptService.ExecuteScriptAsync(code, globals);

        _txtConsole.AppendText(output);
        _txtConsole.AppendText(success ? "[Done] Execution finished successfully.\n" : "[Done] Execution finished with errors.\n");
        _txtConsole.ScrollToEnd();
    }

    private async Task ExecuteReplAsync()
    {
        string expr = _txtRepl.Text.Trim();
        if (string.IsNullOrWhiteSpace(expr)) return;

        _txtRepl.Clear();
        _txtConsole.AppendText($"\nC# > {expr}\n");

        var globals = CreateScriptGlobals();
        string wrapped = expr;
        if (!expr.EndsWith(";") && !expr.StartsWith("Print(") && !expr.Contains("=") && !expr.Contains("foreach") && !expr.Contains("for") && !expr.Contains("if"))
        {
            wrapped = $"Print({expr});";
        }
        else if (!expr.EndsWith(";"))
        {
            wrapped = expr + ";";
        }

        var (success, output, result) = await RoslynScriptService.ExecuteScriptAsync(wrapped, globals);
        _txtConsole.AppendText(output);
        _txtConsole.ScrollToEnd();
    }

    private ScriptGlobals CreateScriptGlobals()
    {
        return new ScriptGlobals
        {
            CurrentProgram = _programModel,
            CurrentAddress = _currentAddress,
            CurrentFunctionName = _currentFunctionName,
            Print = obj => Dispatcher.Invoke(() => _txtConsole.AppendText(obj?.ToString() + "\n")),
            Log = msg => Dispatcher.Invoke(() => _logCallback?.Invoke(msg)),
            JumpTo = addr => Dispatcher.Invoke(() => _jumpCallback($"{addr:X8}")),
            PatchBytes = (addr, bytes) => Dispatcher.Invoke(() =>
            {
                for (int i = 0; i < bytes.Length; i++) _programModel.PatchedBytes[addr + (ulong)i] = bytes[i];
                _logCallback?.Invoke($"[Script] Patched {bytes.Length} bytes at 0x{addr:X8}");
            }),
            Decompile = fn => DecompilerPipeService.DecompileFunction(_programModel, fn, $"{_currentAddress:X8}"),
            Demangle = s => DemanglerService.Demangle(s)
        };
    }
}

public class AttachProcessDialog : Window
{
    public int SelectedProcessId { get; private set; }
    public string SelectedProcessName { get; private set; } = string.Empty;

    public record ProcessItem(int Id, string Name, string Title, string Memory);

    private readonly List<ProcessItem> _allProcesses = new();
    private readonly ListView _lvProcesses;
    private readonly TextBox _txtFilter;

    public AttachProcessDialog()
    {
        Title = "Attach to Running Process (Debugger)";
        Width = 620;
        Height = 460;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        Background = new SolidColorBrush(Color.FromRgb(248, 250, 252));

        var root = new Grid { Margin = new Thickness(14) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Header and Search Filter
        var topPanel = new StackPanel { Orientation = Orientation.Vertical, Margin = new Thickness(0, 0, 0, 10) };
        var lblTitle = new TextBlock
        {
            Text = "Select target process to attach and debug:",
            FontWeight = FontWeights.SemiBold,
            FontSize = 13,
            Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59)),
            Margin = new Thickness(0, 0, 0, 6)
        };
        topPanel.Children.Add(lblTitle);

        var filterGrid = new Grid();
        filterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        filterGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

        var lblFilter = new TextBlock
        {
            Text = "Filter: ",
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = new SolidColorBrush(Color.FromRgb(100, 116, 139)),
            Margin = new Thickness(0, 0, 8, 0)
        };
        Grid.SetColumn(lblFilter, 0);
        filterGrid.Children.Add(lblFilter);

        _txtFilter = new TextBox
        {
            Padding = new Thickness(6, 4, 6, 4),
            FontSize = 12
        };
        _txtFilter.TextChanged += (s, e) => ApplyFilter();
        Grid.SetColumn(_txtFilter, 1);
        filterGrid.Children.Add(_txtFilter);
        topPanel.Children.Add(filterGrid);

        Grid.SetRow(topPanel, 0);
        root.Children.Add(topPanel);

        // Process ListView
        _lvProcesses = new ListView
        {
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 12,
            BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
            BorderThickness = new Thickness(1)
        };
        _lvProcesses.MouseDoubleClick += (s, e) => OnAttach();

        var gv = new GridView();
        gv.Columns.Add(new GridViewColumn { Header = "PID", DisplayMemberBinding = new System.Windows.Data.Binding("Id"), Width = 70 });
        gv.Columns.Add(new GridViewColumn { Header = "Process Name", DisplayMemberBinding = new System.Windows.Data.Binding("Name"), Width = 160 });
        gv.Columns.Add(new GridViewColumn { Header = "Window Title", DisplayMemberBinding = new System.Windows.Data.Binding("Title"), Width = 230 });
        gv.Columns.Add(new GridViewColumn { Header = "Memory", DisplayMemberBinding = new System.Windows.Data.Binding("Memory"), Width = 90 });
        _lvProcesses.View = gv;

        Grid.SetRow(_lvProcesses, 1);
        root.Children.Add(_lvProcesses);

        // Bottom Action Buttons
        var bottomPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0)
        };

        var btnRefresh = new Button
        {
            Content = "🔄 Refresh",
            Padding = new Thickness(12, 5, 12, 5),
            Margin = new Thickness(0, 0, 8, 0),
            Background = new SolidColorBrush(Color.FromRgb(241, 245, 249)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225))
        };
        btnRefresh.Click += (s, e) => LoadProcesses();
        bottomPanel.Children.Add(btnRefresh);

        var btnAttach = new Button
        {
            Content = "🧲 Attach Target",
            Padding = new Thickness(14, 5, 14, 5),
            FontWeight = FontWeights.SemiBold,
            Background = new SolidColorBrush(Color.FromRgb(37, 99, 235)),
            Foreground = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(29, 78, 216)),
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnAttach.Click += (s, e) => OnAttach();
        bottomPanel.Children.Add(btnAttach);

        var btnCancel = new Button
        {
            Content = "Cancel",
            Padding = new Thickness(12, 5, 12, 5),
            Background = new SolidColorBrush(Color.FromRgb(241, 245, 249)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        bottomPanel.Children.Add(btnCancel);

        Grid.SetRow(bottomPanel, 2);
        root.Children.Add(bottomPanel);

        Content = root;
        LoadProcesses();
    }

    private void LoadProcesses()
    {
        _allProcesses.Clear();
        try
        {
            var currentPid = System.Diagnostics.Process.GetCurrentProcess().Id;
            foreach (var p in System.Diagnostics.Process.GetProcesses().OrderBy(p => p.ProcessName))
            {
                if (p.Id == currentPid || p.Id == 0 || p.Id == 4) continue;
                long memMb = 0;
                try { memMb = p.WorkingSet64 / (1024 * 1024); } catch { }
                _allProcesses.Add(new ProcessItem(p.Id, p.ProcessName, p.MainWindowTitle, $"{memMb} MB"));
            }
        }
        catch { }
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        string query = _txtFilter.Text.Trim();
        if (string.IsNullOrEmpty(query))
        {
            _lvProcesses.ItemsSource = _allProcesses.ToList();
        }
        else
        {
            _lvProcesses.ItemsSource = _allProcesses
                .Where(p => p.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                            p.Id.ToString().Contains(query) ||
                            p.Title.Contains(query, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }

    private void OnAttach()
    {
        if (_lvProcesses.SelectedItem is ProcessItem item)
        {
            SelectedProcessId = item.Id;
            SelectedProcessName = item.Name;
            DialogResult = true;
            Close();
        }
        else
        {
            MessageBox.Show("Please select a process from the list.", "Attach Target", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}

public class EditRegisterDialog : Window
{
    public ulong ResultValue { get; private set; }
    private readonly TextBox _txtHex;
    private readonly TextBox _txtDec;
    private readonly RegisterModel _reg;

    public EditRegisterDialog(RegisterModel reg)
    {
        _reg = reg;
        Title = $"Modify Register: {reg.Name}";
        Width = 400;
        Height = 220;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        Background = new SolidColorBrush(Color.FromRgb(248, 250, 252));

        var root = new StackPanel { Margin = new Thickness(14) };

        var lbl = new TextBlock
        {
            Text = $"Edit value for register '{reg.Name}' ({reg.CategoryDisplay}):",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 10),
            Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59))
        };
        root.Children.Add(lbl);

        var grid = new Grid { Margin = new Thickness(0, 0, 0, 12) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(90) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var lblHex = new TextBlock { Text = "Hex Value:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 4) };
        Grid.SetRow(lblHex, 0); Grid.SetColumn(lblHex, 0);
        grid.Children.Add(lblHex);

        _txtHex = new TextBox
        {
            Text = reg.ValueHex,
            FontFamily = new FontFamily("Consolas"),
            Padding = new Thickness(6, 4, 6, 4),
            Margin = new Thickness(0, 4, 0, 4)
        };
        _txtHex.TextChanged += (s, e) =>
        {
            string clean = _txtHex.Text.Trim();
            if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) clean = clean.Substring(2);
            if (ulong.TryParse(clean, System.Globalization.NumberStyles.HexNumber, null, out ulong val))
            {
                _txtDec.Text = val.ToString();
            }
        };
        Grid.SetRow(_txtHex, 0); Grid.SetColumn(_txtHex, 1);
        grid.Children.Add(_txtHex);

        var lblDec = new TextBlock { Text = "Decimal:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 4) };
        Grid.SetRow(lblDec, 1); Grid.SetColumn(lblDec, 0);
        grid.Children.Add(lblDec);

        _txtDec = new TextBox
        {
            Text = reg.ValueDec,
            FontFamily = new FontFamily("Consolas"),
            Padding = new Thickness(6, 4, 6, 4),
            Margin = new Thickness(0, 4, 0, 4)
        };
        _txtDec.TextChanged += (s, e) =>
        {
            if (ulong.TryParse(_txtDec.Text.Trim(), out ulong val))
            {
                _txtHex.Text = $"0x{val:X}";
            }
        };
        Grid.SetRow(_txtDec, 1); Grid.SetColumn(_txtDec, 1);
        grid.Children.Add(_txtDec);

        root.Children.Add(grid);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnOk = new Button
        {
            Content = "Apply Change",
            Padding = new Thickness(14, 5, 14, 5),
            FontWeight = FontWeights.SemiBold,
            Background = new SolidColorBrush(Color.FromRgb(37, 99, 235)),
            Foreground = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(29, 78, 216)),
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnOk.Click += (s, e) =>
        {
            string clean = _txtHex.Text.Trim();
            if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) clean = clean.Substring(2);
            if (ulong.TryParse(clean, System.Globalization.NumberStyles.HexNumber, null, out ulong val))
            {
                ResultValue = val;
                DialogResult = true;
                Close();
            }
            else
            {
                MessageBox.Show("Please enter a valid hexadecimal or decimal integer.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };
        btnPanel.Children.Add(btnOk);

        var btnCancel = new Button
        {
            Content = "Cancel",
            Padding = new Thickness(12, 5, 12, 5),
            Background = new SolidColorBrush(Color.FromRgb(241, 245, 249)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        root.Children.Add(btnPanel);
        Content = root;
    }
}

public class AddBreakpointDialog : Window
{
    public ulong ResultAddress { get; private set; }
    public BreakpointType ResultType { get; private set; } = BreakpointType.Software;
    public string ResultCondition { get; private set; } = string.Empty;

    private readonly TextBox _txtAddress;
    private readonly ComboBox _cmbType;
    private readonly TextBox _txtCondition;

    public AddBreakpointDialog(ulong defaultAddr = 0)
    {
        Title = "Add Breakpoint";
        Width = 420;
        Height = 260;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        WindowStyle = WindowStyle.ToolWindow;
        Background = new SolidColorBrush(Color.FromRgb(248, 250, 252));

        var root = new StackPanel { Margin = new Thickness(14) };

        var lbl = new TextBlock
        {
            Text = "Configure new breakpoint properties:",
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 10),
            Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59))
        };
        root.Children.Add(lbl);

        var grid = new Grid { Margin = new Thickness(0, 0, 0, 12) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        // Address
        var lblAddr = new TextBlock { Text = "Address (Hex):", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 4) };
        Grid.SetRow(lblAddr, 0); Grid.SetColumn(lblAddr, 0);
        grid.Children.Add(lblAddr);

        _txtAddress = new TextBox
        {
            Text = defaultAddr > 0 ? $"0x{defaultAddr:X}" : "0x140001000",
            FontFamily = new FontFamily("Consolas"),
            Padding = new Thickness(6, 4, 6, 4),
            Margin = new Thickness(0, 4, 0, 4)
        };
        Grid.SetRow(_txtAddress, 0); Grid.SetColumn(_txtAddress, 1);
        grid.Children.Add(_txtAddress);

        // Type
        var lblType = new TextBlock { Text = "Type:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 4) };
        Grid.SetRow(lblType, 1); Grid.SetColumn(lblType, 0);
        grid.Children.Add(lblType);

        _cmbType = new ComboBox
        {
            Margin = new Thickness(0, 4, 0, 4),
            Padding = new Thickness(6, 4, 6, 4)
        };
        _cmbType.Items.Add("Software INT3 (0xCC)");
        _cmbType.Items.Add("Hardware Execution (DR0-3)");
        _cmbType.Items.Add("Hardware Write Watchpoint");
        _cmbType.Items.Add("Hardware Read/Write Access");
        _cmbType.SelectedIndex = 0;
        Grid.SetRow(_cmbType, 1); Grid.SetColumn(_cmbType, 1);
        grid.Children.Add(_cmbType);

        // Condition
        var lblCond = new TextBlock { Text = "Condition:", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 4) };
        Grid.SetRow(lblCond, 2); Grid.SetColumn(lblCond, 0);
        grid.Children.Add(lblCond);

        _txtCondition = new TextBox
        {
            Padding = new Thickness(6, 4, 6, 4),
            Margin = new Thickness(0, 4, 0, 4)
        };
        Grid.SetRow(_txtCondition, 2); Grid.SetColumn(_txtCondition, 1);
        grid.Children.Add(_txtCondition);

        root.Children.Add(grid);

        var btnPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        var btnOk = new Button
        {
            Content = "Add Breakpoint",
            Padding = new Thickness(14, 5, 14, 5),
            FontWeight = FontWeights.SemiBold,
            Background = new SolidColorBrush(Color.FromRgb(37, 99, 235)),
            Foreground = Brushes.White,
            BorderBrush = new SolidColorBrush(Color.FromRgb(29, 78, 216)),
            Margin = new Thickness(0, 0, 8, 0)
        };
        btnOk.Click += (s, e) =>
        {
            string clean = _txtAddress.Text.Trim();
            if (clean.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) clean = clean.Substring(2);
            if (clean.EndsWith("h", StringComparison.OrdinalIgnoreCase)) clean = clean.Substring(0, clean.Length - 1);

            if (ulong.TryParse(clean, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            {
                ResultAddress = addr;
                ResultType = _cmbType.SelectedIndex switch
                {
                    1 => BreakpointType.HardwareExecute,
                    2 => BreakpointType.HardwareWrite,
                    3 => BreakpointType.HardwareReadWrite,
                    _ => BreakpointType.Software
                };
                ResultCondition = _txtCondition.Text.Trim();
                DialogResult = true;
                Close();
            }
            else
            {
                MessageBox.Show("Please enter a valid hexadecimal memory address.", "Invalid Address", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };
        btnPanel.Children.Add(btnOk);

        var btnCancel = new Button
        {
            Content = "Cancel",
            Padding = new Thickness(12, 5, 12, 5),
            Background = new SolidColorBrush(Color.FromRgb(241, 245, 249)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225))
        };
        btnCancel.Click += (s, e) => { DialogResult = false; Close(); };
        btnPanel.Children.Add(btnCancel);

        root.Children.Add(btnPanel);
        Content = root;
    }
}


