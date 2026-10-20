using System;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Ghidra.UI.Dialogs;
using Ghidra.UI.Models;
using Ghidra.UI.Services;
using Microsoft.Win32;

namespace Ghidra.UI;

public partial class MainWindow : Window
{
    private ProgramModel _programModel = new();
    private string _currentFunctionName = "main";
    private string _currentAddress = "140001000";

    public MainWindow()
    {
        App.Log("MainWindow constructor start");
        InitializeComponent();
        App.Log("MainWindow InitializeComponent finished");
        SetApplicationIconSafely();
        App.Log("MainWindow SetApplicationIconSafely finished");
        Loaded += MainWindow_Loaded;
        App.Log("MainWindow constructor finished");
    }

    private void SetApplicationIconSafely()
    {
        try
        {
            var uri = new Uri("pack://application:,,,/Assets/app.ico", UriKind.RelativeOrAbsolute);
            Icon = System.Windows.Media.Imaging.BitmapFrame.Create(uri);
        }
        catch
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "app.ico");
                if (File.Exists(path))
                {
                    Icon = System.Windows.Media.Imaging.BitmapFrame.Create(new Uri(path, UriKind.Absolute));
                }
            }
            catch { }
        }
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        Log("================================================================================");
        Log("               Ghidra.NET (C# 14 / .NET 10 WPF) CodeBrowser                ");
        Log("================================================================================");
        Log($"[.NET Runtime] Version: {Environment.Version}");
        Log($"[OS] Platform: {Environment.OSVersion}");

        // Check if native MSVC decompile engine exists
        string nativeDecomp = DecompilerPipeService.FindNativeDecompiler();
        if (File.Exists(nativeDecomp))
        {
            Log($"[Engine] Native MSVC decompiler engine detected: {nativeDecomp}");
        }

        // Check command-line arguments for target binary path
        string[] args = Environment.GetCommandLineArgs();
        string? targetFile = args.Skip(1).FirstOrDefault(a => File.Exists(a));
        if (targetFile == null && args.Length > 1)
        {
            string combined = string.Join(" ", args.Skip(1)).Trim('"');
            if (File.Exists(combined))
            {
                targetFile = combined;
            }
        }

        if (!string.IsNullOrEmpty(targetFile))
        {
            Log($"[Target] Found target binary from command line: {targetFile}");
            LoadProgram(targetFile);
            DecompileCurrentFunction();
        }
        else
        {
            Log("[Ready] No binary loaded. Click '📂 Open Binary' (Ctrl+O) to select a target executable to reverse engineer.");
            Title = "Ghidra.NET - CodeBrowser [No Binary Loaded]";
            SbProgramName.Text = "Program: None";
            SbAddress.Text = "Addr: None";
            TxtArchBadge.Text = "Waiting for binary...";
            TxtDecompilerOutput.Text = "// Welcome to Ghidra.NET CodeBrowser\n// Click '📂 Open Binary' (Ctrl+O) to open and analyze an executable (.exe / .dll).";
        }
    }

    private void LoadProgram(string filePath)
    {
        Log($"\n[PE Loader] Parsing binary target file: {filePath} ...");
        _programModel = PeLoaderService.LoadPeBinary(filePath);
        _currentFunctionName = "main";
        _currentAddress = $"{_programModel.EntryPoint:X8}";
        BindModel();

        if (!string.IsNullOrEmpty(_programModel.StatusMessage))
        {
            Log($"[PE Loader Warning] {_programModel.StatusMessage}");
        }

        Log($"[PE Loader] Loaded: {_programModel.ProgramName} (Arch: {_programModel.Architecture}, ImageBase: 0x{_programModel.ImageBase:X8})");
        Log($"[PE Loader] Sections: {_programModel.Sections.Count}, Imports: {_programModel.IatMap.Count}, EntryPoint: 0x{_programModel.EntryPoint:X8}");
        Log($"[PE Loader] Disassembly generated: {_programModel.ListingLines.Count} instructions. Click '▶ Auto Analyze' to run full analysis.");
    }

    private void BindModel()
    {
        Title = $"Ghidra.NET - CodeBrowser [{_programModel.ProgramName}]";
        TxtArchBadge.Text = $"{_programModel.Architecture} ({_programModel.Compiler})";
        SbProgramName.Text = $"Program: {_programModel.ProgramName} ({_programModel.Format})";
        SbAddress.Text = $"Addr: 0x{_programModel.EntryPoint:X8}";
        TxtSearchAddr.Text = $"{_programModel.EntryPoint:X8}";

        TreeProgram.ItemsSource = null;
        TreeProgram.ItemsSource = _programModel.ProgramTreeNodes;

        TreeSymbols.ItemsSource = null;
        TreeSymbols.ItemsSource = _programModel.SymbolCategories;

        TreeDataTypes.ItemsSource = null;
        TreeDataTypes.ItemsSource = _programModel.DataTypeCategories;

        LvByteViewer.ItemsSource = null;
        LvByteViewer.ItemsSource = _programModel.ByteViewerRows;

        FlowArrowService.UpdateFlowArrows(_programModel);
        LvListing.ItemsSource = null;
        LvListing.ItemsSource = _programModel.ListingLines;

        LvBookmarks.ItemsSource = null;
        LvBookmarks.ItemsSource = _programModel.Bookmarks;
        TxtBookmarkCount.Text = $"{_programModel.Bookmarks.Count} bookmark(s)";

        TreeIncomingCalls.ItemsSource = null;
        TreeIncomingCalls.ItemsSource = _programModel.IncomingCalls;

        TreeOutgoingCalls.ItemsSource = null;
        TreeOutgoingCalls.ItemsSource = _programModel.OutgoingCalls;

        LvPcode.ItemsSource = null;
        LvPcode.ItemsSource = _programModel.CurrentPcodeOps;

        LvEquates.ItemsSource = null;
        LvEquates.ItemsSource = _programModel.Equates;
        TxtEquateCount.Text = $"{_programModel.Equates.Count} equate(s) defined";

        if (_programModel.ListingLines.Count > 0)
        {
            LvListing.SelectedIndex = 0;
            _currentAddress = _programModel.ListingLines[0].Address;
            UpdatePcode(_programModel.ListingLines[0]);
            UpdateCallTree();
        }
    }

    private void DecompileCurrentFunction()
    {
        Log($"\n>>> Decompiling function: {_currentFunctionName} @ 0x{_currentAddress} ...");
        string code = DecompilerPipeService.DecompileFunction(_programModel, _currentFunctionName, _currentAddress, msg => Log(msg));
        TxtDecompilerOutput.Text = code;
        TxtCurrentFunction.Text = $"Scope: {_currentFunctionName}";
        Log($"✓ Function {_currentFunctionName} decompiled successfully (Generated C pseudocode)");

        if (ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out ulong funcAddr))
        {
            RenderFunctionGraph(funcAddr);
        }
    }

    private void TreeSymbols_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is SymbolNode sym)
        {
            if (!string.IsNullOrEmpty(sym.Address))
            {
                JumpToAddress(sym.Address);
                if (sym.SymbolType == "Function")
                {
                    _currentFunctionName = sym.Name;
                    _currentAddress = sym.Address;
                    DecompileCurrentFunction();
                }
            }
        }
    }

    private void TreeDataTypes_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is DataTypeNode dt)
        {
            Log($"[Data Types] Selected: {dt.Name} (Size: {dt.Size}, Kind: {dt.Kind})");
        }
    }

    private void LvByteViewer_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LvByteViewer.SelectedItem is ByteViewerRow row)
        {
            _currentAddress = row.Address;
            SbAddress.Text = $"Addr: 0x{row.Address}";
            TxtSearchAddr.Text = row.Address;
        }
    }

    private void MenuResetLayout_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show("Layout is managed by AvalonDock. You can drag, split, float, or pin any panel.", "Layout Manager", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void TreeProgram_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is ProgramTreeNode node)
        {
            if (node.StartAddress > 0)
            {
                SbSection.Text = $"Section: {node.Name} [{node.Permissions}]";
                JumpToAddress($"{node.StartAddress:X8}");
                Log($"[Program Trees] Jumped to {node.Name} @ 0x{node.StartAddress:X8}");
            }
        }
    }

    private void LvListing_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (LvListing.SelectedItem is ListingItem item)
        {
            _currentAddress = item.Address;
            SbAddress.Text = $"Addr: 0x{item.Address}";
            TxtSearchAddr.Text = item.Address;

            if (!string.IsNullOrEmpty(item.FunctionName))
            {
                _currentFunctionName = item.FunctionName;
                TxtCurrentFunction.Text = $"Scope: {_currentFunctionName}";
            }

            // Sync with ByteViewer
            var byteRow = _programModel.ByteViewerRows.FirstOrDefault(r =>
                r.Address.Equals(item.Address, StringComparison.OrdinalIgnoreCase));
            if (byteRow != null)
            {
                LvByteViewer.SelectedItem = byteRow;
                LvByteViewer.ScrollIntoView(byteRow);
            }

            // Extract primary operand token to highlight across Listing
            if (!string.IsNullOrEmpty(item.Operands))
            {
                var parts = item.Operands.Split(new[] { ',', ' ', '[', ']' }, StringSplitOptions.RemoveEmptyEntries);
                var reg = parts.FirstOrDefault(p =>
                    p.Equals("RAX", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("RBX", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("RCX", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("RDX", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("RSI", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("RDI", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("RBP", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("RSP", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("EAX", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("EBX", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("ECX", StringComparison.OrdinalIgnoreCase) ||
                    p.Equals("EDX", StringComparison.OrdinalIgnoreCase) ||
                    p.StartsWith("R", StringComparison.OrdinalIgnoreCase) ||
                    p.StartsWith("sub_", StringComparison.OrdinalIgnoreCase));

                HighlightOperandTokens(reg ?? (parts.Length > 0 ? parts[0] : ""));
            }
            else
            {
                HighlightOperandTokens("");
            }

            // Sync Decompiler selection to this instruction
            SyncDecompilerToInstruction(item);

            // Sync with P-Code Listing & Call Tree
            UpdatePcode(item);
            UpdateCallTree();
        }
    }

    private void HighlightOperandTokens(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length < 2)
        {
            foreach (var l in _programModel.ListingLines)
            {
                if (l.IsHighlighted) l.IsHighlighted = false;
            }
            return;
        }

        token = token.Trim().ToUpperInvariant();
        token = token.Trim(',', '[', ']', '+', '-', '*', ';');

        if (string.IsNullOrWhiteSpace(token) || token.Length < 2) return;

        foreach (var l in _programModel.ListingLines)
        {
            bool match = l.Operands.ToUpperInvariant().Contains(token) ||
                         l.Instruction.ToUpperInvariant().Equals(token);
            l.IsHighlighted = match;
        }
    }

    private void SyncDecompilerToInstruction(ListingItem item)
    {
        if (string.IsNullOrEmpty(TxtDecompilerOutput.Text)) return;
        string text = TxtDecompilerOutput.Text;

        int idx = -1;
        if (!string.IsNullOrEmpty(item.Address))
        {
            idx = text.IndexOf(item.Address, StringComparison.OrdinalIgnoreCase);
        }
        if (idx < 0 && item.Comment.Contains("Call sub_"))
        {
            int cIdx = item.Comment.IndexOf("sub_");
            if (cIdx >= 0)
            {
                string targetSub = item.Comment.Substring(cIdx).Split(' ')[0];
                idx = text.IndexOf(targetSub, StringComparison.OrdinalIgnoreCase);
            }
        }
        if (idx < 0 && item.Comment.Contains("->"))
        {
            string api = item.Comment.Substring(item.Comment.IndexOf("->") + 2).Trim();
            if (api.Contains('!')) api = api.Substring(api.IndexOf('!') + 1);
            idx = text.IndexOf(api, StringComparison.OrdinalIgnoreCase);
        }
        if (idx < 0 && !string.IsNullOrEmpty(item.FunctionName))
        {
            idx = text.IndexOf(item.FunctionName, StringComparison.OrdinalIgnoreCase);
        }

        if (idx >= 0)
        {
            int lineStart = text.LastIndexOf('\n', idx);
            if (lineStart < 0) lineStart = 0; else lineStart++;
            int lineEnd = text.IndexOf('\n', idx);
            if (lineEnd < 0) lineEnd = text.Length;

            TxtDecompilerOutput.Select(lineStart, lineEnd - lineStart);
        }
    }

    private void JumpToAddress(string targetAddr)
    {
        targetAddr = targetAddr.Trim().ToUpperInvariant();
        if (targetAddr.StartsWith("0X")) targetAddr = targetAddr.Substring(2);

        var match = _programModel.ListingLines.FirstOrDefault(l =>
            l.Address.Equals(targetAddr, StringComparison.OrdinalIgnoreCase) ||
            l.Address.EndsWith(targetAddr, StringComparison.OrdinalIgnoreCase));

        if (match != null)
        {
            LvListing.SelectedItem = match;
            LvListing.ScrollIntoView(match);
            Log($"[Navigation] Navigated to address: 0x{match.Address}");
            return;
        }

        // Dynamically disassemble / generate data lines if outside current listing
        if (ulong.TryParse(targetAddr, System.Globalization.NumberStyles.HexNumber, null, out ulong numAddr))
        {
            var sec = _programModel.FindSection(numAddr);
            if (sec != null && sec.Data != null && sec.Data.Length > 0)
            {
                PeLoaderService.DisassembleRange(_programModel, numAddr, 500);
                match = _programModel.ListingLines.FirstOrDefault(l =>
                    l.Address.Equals(targetAddr, StringComparison.OrdinalIgnoreCase) ||
                    l.Address.EndsWith(targetAddr, StringComparison.OrdinalIgnoreCase));

                if (match != null)
                {
                    LvListing.SelectedItem = match;
                    LvListing.ScrollIntoView(match);
                    Log($"[Navigation] Dynamically disassembled and navigated to address: 0x{match.Address}");
                }
                else
                {
                    var nearest = _programModel.ListingLines
                        .Where(l => ulong.TryParse(l.Address, System.Globalization.NumberStyles.HexNumber, null, out _))
                        .OrderBy(l => Math.Abs((long)(ulong.Parse(l.Address, System.Globalization.NumberStyles.HexNumber) - numAddr)))
                        .FirstOrDefault();
                    if (nearest != null)
                    {
                        LvListing.SelectedItem = nearest;
                        LvListing.ScrollIntoView(nearest);
                        Log($"[Navigation] Navigated to nearest address: 0x{nearest.Address}");
                    }
                }

                // Also populate ByteViewer to view bytes at this address
                PeLoaderService.PopulateByteViewer(_programModel, numAddr);
            }
            else
            {
                Log($"[Navigation] Address 0x{targetAddr} not found in loaded binary ranges.");
            }
        }
        else
        {
            Log($"[Navigation] Invalid hex address: {targetAddr}");
        }
    }

    private void BtnGo_Click(object sender, RoutedEventArgs e)
    {
        JumpToAddress(TxtSearchAddr.Text);
    }

    private void TxtSearchAddr_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            JumpToAddress(TxtSearchAddr.Text);
        }
    }

    private void BtnDecompile_Click(object sender, RoutedEventArgs e)
    {
        DecompileCurrentFunction();
    }

    private void LvListing_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.OemSemicolon || e.Key == Key.Oem1)
        {
            EditComment();
            e.Handled = true;
        }
        else if (e.Key == Key.L)
        {
            RenameSymbol();
            e.Handled = true;
        }
        else if (e.Key == Key.X)
        {
            ShowXRefs();
            e.Handled = true;
        }
        else if (e.Key == Key.Y)
        {
            ApplyDataType();
            e.Handled = true;
        }
        else if (e.Key == Key.N && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
        {
            FillNops();
            e.Handled = true;
        }
        else if (e.Key == Key.E)
        {
            SetEquate();
            e.Handled = true;
        }
        else if (e.Key == Key.F && (Keyboard.Modifiers == ModifierKeys.None))
        {
            ModifyFallthrough();
            e.Handled = true;
        }
        else if (e.Key == Key.A && (Keyboard.Modifiers & ModifierKeys.Shift) != 0)
        {
            PatchInstruction();
            e.Handled = true;
        }
        else if (e.Key == Key.Enter)
        {
            JumpFromListingCurrent();
            e.Handled = true;
        }
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        bool isCtrl = (Keyboard.Modifiers & ModifierKeys.Control) != 0;
        bool isAlt = (Keyboard.Modifiers & ModifierKeys.Alt) != 0;
        bool isShift = (Keyboard.Modifiers & ModifierKeys.Shift) != 0;

        // Ctrl+Alt+P : Patch Instruction / Bytes
        if (isCtrl && isAlt && e.Key == Key.P)
        {
            PatchInstruction();
            e.Handled = true;
            return;
        }

        // Ctrl+D : Toggle Bookmark
        if (isCtrl && !isAlt && e.Key == Key.D)
        {
            MenuToggleBookmark_Click(this, new RoutedEventArgs());
            e.Handled = true;
            return;
        }

        // Ctrl+Shift+F : Global Search Suite
        if (isCtrl && isShift && e.Key == Key.F)
        {
            OpenSearchSuite();
            e.Handled = true;
            return;
        }

        // Ctrl+Shift+C : C Header Parser
        if (isCtrl && isShift && e.Key == Key.C)
        {
            OpenCParser();
            e.Handled = true;
            return;
        }

        // Ctrl+Shift+S : Script Manager & Roslyn Console
        if (isCtrl && isShift && e.Key == Key.S)
        {
            OpenScriptManager();
            e.Handled = true;
            return;
        }

        // Ctrl+O : Open Binary
        if (isCtrl && !isAlt && e.Key == Key.O)
        {
            MenuOpen_Click(this, new RoutedEventArgs());
            e.Handled = true;
            return;
        }

        // Ctrl+S : Export Patched Binary
        if (isCtrl && !isAlt && e.Key == Key.S)
        {
            MenuSavePatched_Click(this, new RoutedEventArgs());
            e.Handled = true;
            return;
        }

        // Ctrl+N : Fill with NOPs
        if (isCtrl && !isAlt && e.Key == Key.N)
        {
            FillNops();
            e.Handled = true;
            return;
        }

        // F5 : Decompile Function
        if (e.Key == Key.F5)
        {
            DecompileCurrentFunction();
            e.Handled = true;
            return;
        }

        // Ctrl+F : Focus search/address box
        if (isCtrl && !isAlt && e.Key == Key.F)
        {
            TxtSearchAddr.Focus();
            TxtSearchAddr.SelectAll();
            e.Handled = true;
            return;
        }

        // If an editable text box currently has focus, don't hijack single keys like G, L, X, Y, ;
        if (e.OriginalSource is TextBox tb && !tb.IsReadOnly)
        {
            return;
        }

        // Single-key shortcuts for reverse engineering
        if (Keyboard.Modifiers == ModifierKeys.None)
        {
            if (e.Key == Key.G)
            {
                TxtSearchAddr.Focus();
                TxtSearchAddr.SelectAll();
                e.Handled = true;
            }
            else if (e.Key == Key.B)
            {
                MenuToggleBookmark_Click(this, new RoutedEventArgs());
                e.Handled = true;
            }
            else if (e.Key == Key.OemSemicolon || e.Key == Key.Oem1)
            {
                EditComment();
                e.Handled = true;
            }
            else if (e.Key == Key.L)
            {
                if (TxtDecompilerOutput.IsKeyboardFocusWithin)
                {
                    RenameDecompilerSymbol();
                }
                else
                {
                    RenameSymbol();
                }
                e.Handled = true;
            }
            else if (e.Key == Key.X)
            {
                ShowXRefs();
                e.Handled = true;
            }
            else if (e.Key == Key.Y)
            {
                ApplyDataType();
                e.Handled = true;
            }
        }
    }

    private void LvListing_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        JumpFromListingCurrent();
    }

    private void JumpFromListingCurrent()
    {
        if (LvListing.SelectedItem is ListingItem item)
        {
            if (item.Comment.Contains("Call sub_"))
            {
                int cIdx = item.Comment.IndexOf("sub_");
                if (cIdx >= 0)
                {
                    string target = item.Comment.Substring(cIdx).Split(' ')[0];
                    JumpToAddress(target);
                    return;
                }
            }
            else if (item.Comment.Contains("->"))
            {
                ShowXRefs();
                return;
            }
            else if (item.IsFunctionHeader)
            {
                ShowXRefs();
            }
        }
    }

    private void EditComment()
    {
        if (LvListing.SelectedItem is not ListingItem item) return;

        string existing = item.Comment;
        if (existing.StartsWith(";")) existing = existing.Substring(1).Trim();

        var dlg = new PromptDialog("Edit Comment (;)", $"Enter comment for instruction @ 0x{item.Address}:", existing);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true)
        {
            string newCmt = dlg.ResultText;
            item.Comment = string.IsNullOrEmpty(newCmt) ? "" : $"; {newCmt}";

            if (ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            {
                _programModel.CustomComments[addr] = newCmt;
            }

            Log($"[Comment] Address 0x{item.Address} comment updated: \"{newCmt}\"");
            DecompileCurrentFunction();
        }
    }

    private void RenameSymbol(string? targetSymbol = null)
    {
        string curSymbol = targetSymbol ?? _currentFunctionName;

        if (LvListing.SelectedItem is ListingItem item)
        {
            if (item.Comment.Contains("Call sub_"))
            {
                int cIdx = item.Comment.IndexOf("sub_");
                if (cIdx >= 0)
                {
                    curSymbol = item.Comment.Substring(cIdx).Split(' ')[0];
                }
            }
            else if (!string.IsNullOrEmpty(item.FunctionName))
            {
                curSymbol = item.FunctionName;
            }
        }

        var dlg = new PromptDialog("Rename Symbol / Function (L)", $"Enter new name for symbol '{curSymbol}':", curSymbol);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true && !string.IsNullOrEmpty(dlg.ResultText) && dlg.ResultText != curSymbol)
        {
            string newName = dlg.ResultText;
            _programModel.RenamedSymbols[curSymbol] = newName;

            // 1. Update Listing Lines
            foreach (var l in _programModel.ListingLines)
            {
                if (l.FunctionName == curSymbol)
                {
                    l.FunctionName = newName;
                    if (l.IsFunctionHeader)
                    {
                        l.Comment = l.Comment.Replace(curSymbol, newName);
                    }
                }
                if (l.Comment.Contains(curSymbol))
                {
                    l.Comment = l.Comment.Replace(curSymbol, newName);
                }
                if (l.Operands.Contains(curSymbol))
                {
                    l.Operands = l.Operands.Replace(curSymbol, newName);
                }
            }

            // 2. Update Symbol Tree
            var fnCat = _programModel.SymbolCategories.FirstOrDefault(c => c.Name == "Functions");
            if (fnCat != null)
            {
                var symNode = fnCat.Children.FirstOrDefault(s => s.Name == curSymbol);
                if (symNode != null)
                {
                    symNode.Name = newName;
                    symNode.Signature = $"void {newName}()";
                }
            }

            // 3. Update active function scope
            if (_currentFunctionName == curSymbol)
            {
                _currentFunctionName = newName;
                TxtCurrentFunction.Text = $"Scope: {_currentFunctionName}";
            }

            Log($"[Rename] Symbol '{curSymbol}' successfully renamed to '{newName}'.");
            DecompileCurrentFunction();
        }
    }

    private void ShowXRefs()
    {
        ulong targetAddr = 0;
        string symbolName = _currentFunctionName;

        if (LvListing.SelectedItem is ListingItem item)
        {
            if (item.Comment.Contains("Call sub_"))
            {
                int cIdx = item.Comment.IndexOf("sub_");
                if (cIdx >= 0 && cIdx + 4 < item.Comment.Length)
                {
                    string hexPart = item.Comment.Substring(cIdx + 4).Split(' ')[0];
                    if (ulong.TryParse(hexPart, System.Globalization.NumberStyles.HexNumber, null, out ulong tAddr))
                    {
                        targetAddr = tAddr;
                        symbolName = $"sub_{hexPart}";
                    }
                }
            }
            if (targetAddr == 0)
            {
                ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out targetAddr);
                symbolName = !string.IsNullOrEmpty(item.FunctionName) ? item.FunctionName : $"0x{item.Address}";
            }
        }
        else
        {
            ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out targetAddr);
        }

        if (targetAddr != 0 && _programModel.XRefs.TryGetValue(targetAddr, out var refs) && refs.Count > 0)
        {
            var win = new XRefsWindow(symbolName, targetAddr, refs, addr => JumpToAddress($"{addr:X8}"));
            win.Owner = this;
            win.ShowDialog();
        }
        else
        {
            MessageBox.Show(
                $"No cross-references (CALL/JUMP/DATA) found targeting address 0x{targetAddr:X8}.\n\nTip: Click '▶ Auto Analyze' to run a deep reference scan across the whole binary.",
                "Cross References (XREFs)",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }

    private void TxtDecompilerOutput_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        JumpDecompilerSymbol();
    }

    private void TxtDecompilerOutput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.L)
        {
            RenameDecompilerSymbol();
            e.Handled = true;
        }
        else if (e.Key == Key.X)
        {
            ShowXRefs();
            e.Handled = true;
        }
        else if (e.Key == Key.Enter)
        {
            JumpDecompilerSymbol();
            e.Handled = true;
        }
    }

    private void TxtDecompilerOutput_SelectionChanged(object sender, RoutedEventArgs e)
    {
        string sel = TxtDecompilerOutput.SelectedText;
        if (!string.IsNullOrWhiteSpace(sel))
        {
            HighlightOperandTokens(sel.Trim());
        }
        else
        {
            int caret = TxtDecompilerOutput.CaretIndex;
            string text = TxtDecompilerOutput.Text;
            if (caret >= 0 && caret < text.Length)
            {
                int start = caret;
                while (start > 0 && (char.IsLetterOrDigit(text[start - 1]) || text[start - 1] == '_')) start--;
                int end = caret;
                while (end < text.Length && (char.IsLetterOrDigit(text[end]) || text[end] == '_')) end++;
                if (end > start)
                {
                    string word = text.Substring(start, end - start).Trim();
                    HighlightOperandTokens(word);
                }
            }
        }
    }

    private void MenuRenameDecompilerSymbol_Click(object sender, RoutedEventArgs e)
    {
        RenameDecompilerSymbol();
    }

    private void RenameDecompilerSymbol()
    {
        string sel = TxtDecompilerOutput.SelectedText;
        if (string.IsNullOrWhiteSpace(sel))
        {
            sel = _currentFunctionName;
        }
        RenameSymbol(sel.Trim());
    }

    private void MenuJumpDecompilerSymbol_Click(object sender, RoutedEventArgs e)
    {
        JumpDecompilerSymbol();
    }

    private void JumpDecompilerSymbol()
    {
        string text = TxtDecompilerOutput.Text;
        if (string.IsNullOrEmpty(text)) return;

        int caret = TxtDecompilerOutput.CaretIndex;
        if (caret < 0 || caret >= text.Length) return;

        // Extract identifier word at caret
        int start = caret;
        while (start > 0 && (char.IsLetterOrDigit(text[start - 1]) || text[start - 1] == '_' || text[start - 1] == 'x' || text[start - 1] == 'X'))
        {
            start--;
        }
        int end = caret;
        while (end < text.Length && (char.IsLetterOrDigit(text[end]) || text[end] == '_' || text[end] == 'x' || text[end] == 'X'))
        {
            end++;
        }

        if (end > start)
        {
            string word = text.Substring(start, end - start).Trim();
            Log($"[Decompiler] Clicked symbol: '{word}'");

            if (word.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                JumpToAddress(word.Substring(2));
                return;
            }

            if (word.StartsWith("sub_", StringComparison.OrdinalIgnoreCase))
            {
                JumpToAddress(word.Substring(4));
                return;
            }

            // Check if symbol matches a function in Symbol Tree
            var fnCat = _programModel.SymbolCategories.FirstOrDefault(c => c.Name == "Functions");
            if (fnCat != null)
            {
                var sNode = fnCat.Children.FirstOrDefault(s => s.Name.Equals(word, StringComparison.OrdinalIgnoreCase));
                if (sNode != null && !string.IsNullOrEmpty(sNode.Address))
                {
                    JumpToAddress(sNode.Address);
                    return;
                }
            }

            // Check if symbol matches a function in Listing
            var matchFunc = _programModel.ListingLines.FirstOrDefault(l =>
                l.FunctionName.Equals(word, StringComparison.OrdinalIgnoreCase));
            if (matchFunc != null)
            {
                JumpToAddress(matchFunc.Address);
                return;
            }

            // Check if matches an imported API
            var matchIat = _programModel.IatMap.FirstOrDefault(kvp =>
                kvp.Value.EndsWith(word, StringComparison.OrdinalIgnoreCase) ||
                kvp.Value.Equals(word, StringComparison.OrdinalIgnoreCase));
            if (matchIat.Key != 0)
            {
                JumpToAddress($"{matchIat.Key:X8}");
                return;
            }

            // Otherwise, jump to symbol or address if valid hex
            JumpToAddress(word);
        }
    }

    private void MenuCopyAddress_Click(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_currentAddress))
        {
            Clipboard.SetText(_currentAddress);
            Log($"[Clipboard] Copied address: 0x{_currentAddress}");
        }
    }

    private void MenuEditComment_Click(object sender, RoutedEventArgs e)
    {
        EditComment();
    }

    private void MenuRenameSymbol_Click(object sender, RoutedEventArgs e)
    {
        RenameSymbol();
    }

    private void MenuShowXRefs_Click(object sender, RoutedEventArgs e)
    {
        ShowXRefs();
    }

    private void MenuOpen_Click(object sender, RoutedEventArgs e)
    {
        var ofd = new OpenFileDialog
        {
            Title = "Select Target Executable to Reverse Engineer (PE / ELF / Binary)",
            Filter = "PE Executables (*.exe;*.dll)|*.exe;*.dll|All Files (*.*)|*.*"
        };

        if (ofd.ShowDialog() == true)
        {
            LoadProgram(ofd.FileName);
            DecompileCurrentFunction();
        }
    }

    private void MenuAnalyze_Click(object sender, RoutedEventArgs e)
    {
        PeLoaderService.RunAutoAnalysis(_programModel, msg => Log(msg));
        BindModel();
        DecompileCurrentFunction();

        MessageBox.Show(
            $"Auto Analysis Complete!\n\n" +
            $"• Discovered Functions: {_programModel.FunctionAddresses.Count}\n" +
            $"• Cross-References (XREFs): {_programModel.XRefs.Values.Sum(v => v.Count)}\n" +
            $"• Imported APIs: {_programModel.IatMap.Count}\n" +
            $"• Sections: {_programModel.Sections.Count}\n" +
            $"• Instructions: {_programModel.ListingLines.Count:N0}",
            "Ghidra.NET Analysis",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void MenuAbout_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(
            "Ghidra.NET (C# 14 / .NET 10)\n\n" +
            "• Pure C# port of the Ghidra Software Reverse Engineering framework\n" +
            "• Core Architecture: 15,692 Java files transpiled 1:1 to C#\n" +
            "• Native Decompiler: Native MSVC C++ decompile.exe with bidirectional IPC pipe\n" +
            "• Presentation: Windows Presentation Foundation (.NET 10 WPF)\n\n" +
            "Ghidra.NET Team 2026",
            "About Ghidra.NET",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void MenuExit_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void MenuPatchInstruction_Click(object sender, RoutedEventArgs e)
    {
        PatchInstruction();
    }

    private void PatchInstruction()
    {
        ulong addr = 0;
        string origBytes = "";
        string origInstr = "";

        if (LvListing.SelectedItem is ListingItem item)
        {
            ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out addr);
            origBytes = item.Bytes;
            origInstr = $"{item.Instruction} {item.Operands}".Trim();
        }
        else if (ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out ulong curA))
        {
            addr = curA;
            var match = _programModel.ListingLines.FirstOrDefault(l => l.Address.Equals(_currentAddress, StringComparison.OrdinalIgnoreCase));
            if (match != null)
            {
                origBytes = match.Bytes;
                origInstr = $"{match.Instruction} {match.Operands}".Trim();
            }
        }

        if (addr == 0)
        {
            MessageBox.Show("Please select an instruction or address to patch.", "Patch", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dlg = new PatchInstructionDialog(addr, origBytes, origInstr);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true && dlg.ResultBytes.Length > 0)
        {
            PeLoaderService.ApplyPatch(_programModel, addr, dlg.ResultBytes, msg => Log(msg));
            TxtByteViewerPatchedCount.Text = $"Patched: {_programModel.PatchedBytes.Count} bytes";
            DecompileCurrentFunction();
        }
    }

    private void MenuFillNops_Click(object sender, RoutedEventArgs e)
    {
        FillNops();
    }

    private void FillNops()
    {
        if (LvListing.SelectedItem is ListingItem item && ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
        {
            int byteCount = Math.Max(1, item.Bytes.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).Length);
            byte[] nopBytes = System.Linq.Enumerable.Repeat((byte)0x90, byteCount).ToArray();
            PeLoaderService.ApplyPatch(_programModel, addr, nopBytes, msg => Log(msg));
            TxtByteViewerPatchedCount.Text = $"Patched: {_programModel.PatchedBytes.Count} bytes";
            DecompileCurrentFunction();
        }
        else
        {
            MessageBox.Show("Please select an instruction in the Listing to fill with NOPs.", "Fill NOPs", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void MenuEditHexRow_Click(object sender, RoutedEventArgs e)
    {
        EditHexRow();
    }

    private void LvByteViewer_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        EditHexRow();
    }

    private void LvByteViewer_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Space || e.Key == Key.F2)
        {
            EditHexRow();
            e.Handled = true;
        }
        else if (e.Key == Key.Enter)
        {
            if (LvByteViewer.SelectedItem is ByteViewerRow row)
            {
                JumpToAddress(row.Address);
                e.Handled = true;
            }
        }
    }

    private void EditHexRow()
    {
        if (LvByteViewer.SelectedItem is not ByteViewerRow row) return;

        var dlg = new ByteEditDialog(row.Address, row.Hex0_3, row.Hex4_7, row.Hex8_B, row.HexC_F);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true && dlg.ResultBytes.Length > 0)
        {
            if (ulong.TryParse(row.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            {
                PeLoaderService.ApplyPatch(_programModel, addr, dlg.ResultBytes, msg => Log(msg));
                TxtByteViewerPatchedCount.Text = $"Patched: {_programModel.PatchedBytes.Count} bytes";
                DecompileCurrentFunction();
            }
        }
    }

    private void MenuFillByteRowNops_Click(object sender, RoutedEventArgs e)
    {
        if (LvByteViewer.SelectedItem is ByteViewerRow row && ulong.TryParse(row.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
        {
            byte[] nopBytes = System.Linq.Enumerable.Repeat((byte)0x90, 16).ToArray();
            PeLoaderService.ApplyPatch(_programModel, addr, nopBytes, msg => Log(msg));
            TxtByteViewerPatchedCount.Text = $"Patched: {_programModel.PatchedBytes.Count} bytes";
            DecompileCurrentFunction();
        }
    }

    private void MenuRevertPatches_Click(object sender, RoutedEventArgs e)
    {
        if (_programModel.PatchedBytes.Count == 0)
        {
            MessageBox.Show("No patches currently applied to revert.", "Revert Patches", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MessageBox.Show($"Are you sure you want to revert all {_programModel.PatchedBytes.Count} patched byte(s)?", "Revert Patches", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            if (!string.IsNullOrEmpty(_programModel.FilePath) && File.Exists(_programModel.FilePath))
            {
                LoadProgram(_programModel.FilePath);
                _programModel.PatchedBytes.Clear();
                TxtByteViewerPatchedCount.Text = "Patched: 0 bytes";
                DecompileCurrentFunction();
                Log("[Patch Engine] All patches reverted to original binary state.");
            }
        }
    }

    private void MenuJumpToByteAddress_Click(object sender, RoutedEventArgs e)
    {
        if (LvByteViewer.SelectedItem is ByteViewerRow row)
        {
            JumpToAddress(row.Address);
        }
    }

    private void MenuSavePatched_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_programModel.FilePath) || !File.Exists(_programModel.FilePath))
        {
            MessageBox.Show("No valid executable binary currently loaded.", "Export Error", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string defaultName = Path.GetFileNameWithoutExtension(_programModel.FilePath) + "_patched" + Path.GetExtension(_programModel.FilePath);
        var sfd = new SaveFileDialog
        {
            Title = "Export Patched Executable (PE / Binary)",
            FileName = defaultName,
            Filter = "Executable Files (*.exe;*.dll)|*.exe;*.dll|All Files (*.*)|*.*"
        };

        if (sfd.ShowDialog() == true)
        {
            try
            {
                int count = PeLoaderService.ExportPatchedBinary(_programModel, sfd.FileName, msg => Log(msg));
                MessageBox.Show(
                    $"Successfully exported patched binary!\n\n" +
                    $"• Destination: {sfd.FileName}\n" +
                    $"• Patched Bytes: {count:N0}\n\n" +
                    $"The patched file is ready to execute or distribute.",
                    "Export Patched Binary",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to export patched binary:\n{ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    private void MenuCreateStructure_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new StructureEditorDialog();
        dlg.Owner = this;
        if (dlg.ShowDialog() == true)
        {
            _programModel.CustomStructures.Add(dlg.StructModel);
            PeLoaderService.PopulateDataTypes(_programModel);
            TreeDataTypes.ItemsSource = null;
            TreeDataTypes.ItemsSource = _programModel.DataTypeCategories;
            Log($"[Data Type Manager] Created structure '{dlg.StructModel.Name}' ({dlg.StructModel.TotalSize} bytes, {dlg.StructModel.Fields.Count} fields).");
            DecompileCurrentFunction();
        }
    }

    private void MenuApplyDataType_Click(object sender, RoutedEventArgs e)
    {
        ApplyDataType();
    }

    private void ApplyDataType()
    {
        ulong addr = 0;
        if (LvListing.SelectedItem is ListingItem item)
        {
            ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out addr);
        }
        else
        {
            ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out addr);
        }

        if (addr == 0)
        {
            MessageBox.Show("Please select an instruction or address to apply a data type.", "Apply Type", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dlg = new ApplyDataTypeDialog(addr, _programModel);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true && !string.IsNullOrEmpty(dlg.SelectedTypeName))
        {
            _programModel.AppliedTypes[addr] = dlg.SelectedTypeName;

            var match = _programModel.ListingLines.FirstOrDefault(l =>
                ulong.TryParse(l.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong la) && la == addr);
            if (match != null)
            {
                match.Comment = $"; [Type: {dlg.SelectedTypeName}] " + match.Comment.Replace($"; [Type: {dlg.SelectedTypeName}] ", "");
            }

            Log($"[Data Types] Applied type '{dlg.SelectedTypeName}' to address 0x{addr:X8}.");
            DecompileCurrentFunction();
        }
    }

    private void TreeDataTypes_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (TreeDataTypes.SelectedItem is DataTypeNode dt)
        {
            if (dt.Kind == "Struct")
            {
                var matchStruct = _programModel.CustomStructures.FirstOrDefault(s => s.Name == dt.Name);
                if (matchStruct != null)
                {
                    var dlg = new StructureEditorDialog(matchStruct);
                    dlg.Owner = this;
                    if (dlg.ShowDialog() == true)
                    {
                        PeLoaderService.PopulateDataTypes(_programModel);
                        TreeDataTypes.ItemsSource = null;
                        TreeDataTypes.ItemsSource = _programModel.DataTypeCategories;
                        DecompileCurrentFunction();
                    }
                }
            }
            else if (dt.Kind == "Enum")
            {
                var matchEnum = _programModel.CustomEnums.FirstOrDefault(en => en.Name == dt.Name);
                if (matchEnum != null)
                {
                    var dlg = new EnumEditorDialog(matchEnum);
                    dlg.Owner = this;
                    if (dlg.ShowDialog() == true)
                    {
                        PeLoaderService.PopulateDataTypes(_programModel);
                        TreeDataTypes.ItemsSource = null;
                        TreeDataTypes.ItemsSource = _programModel.DataTypeCategories;
                        Log($"[Data Types] Updated enum: {dlg.ResultEnum.Name}");
                    }
                }
            }
        }
    }

    private void MenuCreateEnum_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new EnumEditorDialog();
        dlg.Owner = this;
        if (dlg.ShowDialog() == true && dlg.ResultEnum != null)
        {
            _programModel.CustomEnums.Add(dlg.ResultEnum);
            PeLoaderService.PopulateDataTypes(_programModel);
            TreeDataTypes.ItemsSource = null;
            TreeDataTypes.ItemsSource = _programModel.DataTypeCategories;
            Log($"[Data Types] Created custom enum: {dlg.ResultEnum.Name} ({dlg.ResultEnum.Members.Count} members)");
        }
    }

    private void TxtSymbolFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        string query = TxtSymbolFilter.Text.Trim();
        if (string.IsNullOrEmpty(query))
        {
            TreeSymbols.ItemsSource = _programModel.SymbolCategories;
            return;
        }

        var filtered = new System.Collections.ObjectModel.ObservableCollection<SymbolNode>();
        foreach (var cat in _programModel.SymbolCategories)
        {
            var matching = cat.Children.Where(c => c.Name.Contains(query, StringComparison.OrdinalIgnoreCase) || c.Address.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
            if (matching.Count > 0)
            {
                var newCat = new SymbolNode { Name = $"{cat.Name} ({matching.Count})", Icon = cat.Icon };
                foreach (var m in matching) newCat.Children.Add(m);
                filtered.Add(newCat);
            }
        }
        TreeSymbols.ItemsSource = filtered;
    }

    private void TxtDataTypeFilter_TextChanged(object sender, TextChangedEventArgs e)
    {
        string query = TxtDataTypeFilter.Text.Trim();
        if (string.IsNullOrEmpty(query))
        {
            TreeDataTypes.ItemsSource = _programModel.DataTypeCategories;
            return;
        }

        var filtered = new System.Collections.ObjectModel.ObservableCollection<DataTypeNode>();
        foreach (var cat in _programModel.DataTypeCategories)
        {
            var matching = cat.Children.Where(c => c.Name.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
            if (matching.Count > 0)
            {
                var newCat = new DataTypeNode { Name = $"{cat.Name} ({matching.Count})", Icon = cat.Icon, Kind = cat.Kind };
                foreach (var m in matching) newCat.Children.Add(m);
                filtered.Add(newCat);
            }
        }
        TreeDataTypes.ItemsSource = filtered;
    }

    private void MenuToggleBookmark_Click(object sender, RoutedEventArgs e)
    {
        ulong addr = 0;
        string func = _currentFunctionName;
        if (LvListing.SelectedItem is ListingItem item)
        {
            ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out addr);
            func = item.FunctionName;
        }
        else
        {
            ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out addr);
        }

        if (addr == 0) return;

        var existing = _programModel.Bookmarks.FirstOrDefault(b => b.Address == addr);
        var dlg = new BookmarkDialog(addr, existing?.Category ?? "Note", existing?.Description ?? "", existing != null);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true)
        {
            if (dlg.DeleteRequested)
            {
                if (existing != null) _programModel.Bookmarks.Remove(existing);
                var line = _programModel.ListingLines.FirstOrDefault(l => l.Address.Equals($"{addr:X8}", StringComparison.OrdinalIgnoreCase));
                if (line != null)
                {
                    line.IsBookmarked = false;
                    line.BookmarkText = "";
                }
            }
            else
            {
                BookmarkService.ToggleBookmark(_programModel, addr, dlg.Category, dlg.Description);
            }

            TxtBookmarkCount.Text = $"{_programModel.Bookmarks.Count} bookmark(s)";
            LvBookmarks.ItemsSource = null;
            LvBookmarks.ItemsSource = _programModel.Bookmarks;
            Log($"[Bookmarks] Updated bookmark @ 0x{addr:X8} ({dlg.Category}: {dlg.Description})");
        }
    }

    private void BtnDeleteBookmark_Click(object sender, RoutedEventArgs e)
    {
        if (LvBookmarks.SelectedItem is BookmarkItem bm)
        {
            _programModel.Bookmarks.Remove(bm);
            var line = _programModel.ListingLines.FirstOrDefault(l => l.Address.Equals($"{bm.Address:X8}", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                line.IsBookmarked = false;
                line.BookmarkText = "";
            }
            TxtBookmarkCount.Text = $"{_programModel.Bookmarks.Count} bookmark(s)";
            Log($"[Bookmarks] Removed bookmark @ {bm.AddressHex}");
        }
    }

    private void LvBookmarks_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (LvBookmarks.SelectedItem is BookmarkItem bm)
        {
            JumpToAddress($"{bm.Address:X8}");
        }
    }

    private void MenuSearchSuite_Click(object sender, RoutedEventArgs e)
    {
        OpenSearchSuite();
    }

    private void OpenSearchSuite()
    {
        var dlg = new SearchSuiteDialog(_programModel);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true && dlg.SelectedAddress.HasValue)
        {
            JumpToAddress($"{dlg.SelectedAddress.Value:X8}");
        }
    }

    private void MenuSearchStrings_Click(object sender, RoutedEventArgs e)
    {
        BtnQuickSearchStrings_Click(sender, e);
    }

    private void MenuSearchHex_Click(object sender, RoutedEventArgs e)
    {
        BtnQuickSearchHex_Click(sender, e);
    }

    private void MenuSearchScalars_Click(object sender, RoutedEventArgs e)
    {
        BtnQuickSearchScalars_Click(sender, e);
    }

    private void TxtQuickSearch_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            BtnQuickSearchStrings_Click(sender, e);
        }
    }

    private void BtnQuickSearchStrings_Click(object sender, RoutedEventArgs e)
    {
        var res = SearchService.SearchStrings(_programModel, TxtQuickSearch.Text);
        LvSearchResults.ItemsSource = res;
        TxtSearchResultCount.Text = $"{res.Count} string(s) found";
        Log($"[Search Suite] Found {res.Count} strings matching '{TxtQuickSearch.Text}'");
    }

    private void BtnQuickSearchHex_Click(object sender, RoutedEventArgs e)
    {
        var res = SearchService.SearchHexBytes(_programModel, TxtQuickSearch.Text);
        LvSearchResults.ItemsSource = res;
        TxtSearchResultCount.Text = $"{res.Count} match(es) found";
        Log($"[Search Suite] Found {res.Count} hex byte sequence matches for '{TxtQuickSearch.Text}'");
    }

    private void BtnQuickSearchScalars_Click(object sender, RoutedEventArgs e)
    {
        var res = SearchService.SearchScalars(_programModel, TxtQuickSearch.Text);
        LvSearchResults.ItemsSource = res;
        TxtSearchResultCount.Text = $"{res.Count} scalar(s) found";
        Log($"[Search Suite] Found {res.Count} scalar matches for '{TxtQuickSearch.Text}'");
    }

    private void LvSearchResults_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (LvSearchResults.SelectedItem is SearchResultItem item)
        {
            JumpToAddress($"{item.Address:X8}");
        }
    }

    private void BtnRefreshGraph_Click(object sender, RoutedEventArgs e)
    {
        if (ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out ulong funcAddr))
        {
            RenderFunctionGraph(funcAddr);
        }
    }

    private void BtnGraphZoomIn_Click(object sender, RoutedEventArgs e)
    {
        GraphScaleTransform.ScaleX = Math.Min(2.5, GraphScaleTransform.ScaleX + 0.15);
        GraphScaleTransform.ScaleY = Math.Min(2.5, GraphScaleTransform.ScaleY + 0.15);
    }

    private void BtnGraphZoomOut_Click(object sender, RoutedEventArgs e)
    {
        GraphScaleTransform.ScaleX = Math.Max(0.3, GraphScaleTransform.ScaleX - 0.15);
        GraphScaleTransform.ScaleY = Math.Max(0.3, GraphScaleTransform.ScaleY - 0.15);
    }

    private void BtnGraphResetView_Click(object sender, RoutedEventArgs e)
    {
        GraphScaleTransform.ScaleX = 1.0;
        GraphScaleTransform.ScaleY = 1.0;
        ScrollGraph.ScrollToHome();
    }

    private void RenderFunctionGraph(ulong functionAddress)
    {
        var cfg = ControlFlowGraphService.BuildGraph(_programModel, functionAddress);
        TxtGraphFunctionLabel.Text = $"Function: {cfg.FunctionName} ({cfg.Blocks.Count} Basic Blocks, {cfg.Edges.Count} Edges)";

        CanvasEdges.Children.Clear();
        CanvasBlocks.Children.Clear();

        GridGraphContainer.Width = cfg.CanvasWidth;
        GridGraphContainer.Height = cfg.CanvasHeight;

        // Render Edges
        foreach (var edge in cfg.Edges)
        {
            var brush = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(edge.StrokeColor));

            var path = new System.Windows.Shapes.Path
            {
                Stroke = brush,
                StrokeThickness = 2.0,
                Data = System.Windows.Media.Geometry.Parse($"M {edge.StartX},{edge.StartY} C {edge.StartX},{edge.StartY + 30} {edge.EndX},{edge.EndY - 30} {edge.EndX},{edge.EndY}")
            };
            CanvasEdges.Children.Add(path);

            if (!string.IsNullOrEmpty(edge.ArrowHeadData))
            {
                var arrow = new System.Windows.Shapes.Path
                {
                    Fill = brush,
                    Data = System.Windows.Media.Geometry.Parse(edge.ArrowHeadData)
                };
                CanvasEdges.Children.Add(arrow);
            }
        }

        // Render Blocks
        foreach (var block in cfg.Blocks)
        {
            var border = new Border
            {
                Width = block.Width,
                Height = block.Height,
                Background = System.Windows.Media.Brushes.White,
                BorderBrush = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(block.BorderColor)),
                BorderThickness = new Thickness(block.BorderThickness),
                CornerRadius = new CornerRadius(5),
                ClipToBounds = true,
                Effect = new System.Windows.Media.Effects.DropShadowEffect
                {
                    Color = System.Windows.Media.Colors.Black,
                    Direction = 270,
                    ShadowDepth = 2,
                    Opacity = 0.15,
                    BlurRadius = 4
                }
            };

            var dock = new DockPanel();

            // Header
            var header = new Border
            {
                Background = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(block.HeaderBackground)),
                BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xCB, 0xD5, 0xE1)),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(6, 4, 6, 4)
            };
            DockPanel.SetDock(header, Dock.Top);

            var spHeader = new StackPanel { Orientation = Orientation.Horizontal };
            spHeader.Children.Add(new TextBlock
            {
                Text = block.Label,
                FontWeight = FontWeights.Bold,
                FontSize = 11,
                Foreground = new System.Windows.Media.SolidColorBrush((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(block.HeaderForeground))
            });
            spHeader.Children.Add(new TextBlock
            {
                Text = $" [0x{block.StartAddress:X8}]",
                FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                FontSize = 10,
                Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x64, 0x74, 0x8B)),
                Margin = new Thickness(4, 0, 0, 0)
            });
            header.Child = spHeader;
            dock.Children.Add(header);

            // Instructions Body
            var spInstrs = new StackPanel { Margin = new Thickness(6, 4, 6, 4) };
            foreach (var ins in block.Instructions)
            {
                var spLine = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 1, 0, 1) };
                spLine.Children.Add(new TextBlock
                {
                    Text = ins.Address,
                    Width = 70,
                    FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                    FontSize = 10,
                    Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x02, 0x84, 0xC7))
                });
                spLine.Children.Add(new TextBlock
                {
                    Text = ins.Instruction,
                    Width = 55,
                    FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                    FontSize = 10,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x93, 0x33, 0xEA))
                });
                spLine.Children.Add(new TextBlock
                {
                    Text = ins.Operands,
                    FontFamily = new System.Windows.Media.FontFamily("Consolas"),
                    FontSize = 10,
                    Foreground = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1E, 0x29, 0x3B))
                });
                spInstrs.Children.Add(spLine);
            }
            dock.Children.Add(spInstrs);

            border.Child = dock;
            Canvas.SetLeft(border, block.X);
            Canvas.SetTop(border, block.Y);

            border.MouseLeftButtonDown += (s, e) =>
            {
                JumpToAddress($"{block.StartAddress:X8}");
                foreach (var b in cfg.Blocks) b.IsSelected = (b.Id == block.Id);
                border.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x25, 0x63, 0xEB));
                border.BorderThickness = new Thickness(2.5);
                if (e.ClickCount >= 2)
                {
                    JumpToAddress($"{block.StartAddress:X8}");
                }
            };

            CanvasBlocks.Children.Add(border);
        }

        // Render Minimap
        RenderMinimap(cfg);
    }

    private void RenderMinimap(ControlFlowGraph cfg)
    {
        CanvasMinimap.Children.Clear();
        if (cfg.CanvasWidth <= 0 || cfg.CanvasHeight <= 0) return;

        double scaleX = 170.0 / cfg.CanvasWidth;
        double scaleY = 110.0 / cfg.CanvasHeight;
        double scale = Math.Min(scaleX, scaleY);

        foreach (var b in cfg.Blocks)
        {
            var rect = new System.Windows.Shapes.Rectangle
            {
                Width = Math.Max(4, b.Width * scale),
                Height = Math.Max(3, b.Height * scale),
                Fill = b.IsEntryBlock ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x16, 0xA3, 0x4A)) : (b.IsReturnBlock ? new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xD9, 0x77, 0x06)) : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8))),
                Stroke = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x64, 0x74, 0x8B)),
                StrokeThickness = 0.5
            };
            Canvas.SetLeft(rect, b.X * scale);
            Canvas.SetTop(rect, b.Y * scale);
            CanvasMinimap.Children.Add(rect);
        }
    }

    private void BtnClearLog_Click(object sender, RoutedEventArgs e)
    {
        TxtLog.Clear();
    }

    private void Log(string message)
    {
        App.Log(message);
        TxtLog.AppendText(message + "\n");
        TxtLog.ScrollToEnd();
    }

    // =========================================================================
    // Tier 1 Enhancements: P-Code, Call Tree, Equates, Memory Map, Function Comparison
    // =========================================================================

    private void UpdatePcode(ListingItem? item)
    {
        if (item == null || LvPcode == null) return;

        _programModel.CurrentPcodeOps.Clear();

        if (ChkPcodeFunction != null && ChkPcodeFunction.IsChecked == true)
        {
            ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out ulong funcAddr);
            var insts = CallTreeService.GetFunctionInstructions(_programModel, funcAddr, _currentFunctionName);
            foreach (var inst in insts)
            {
                var ops = PcodeService.GeneratePcode(inst);
                foreach (var op in ops) _programModel.CurrentPcodeOps.Add(op);
            }
            if (TxtPcodeHeader != null)
                TxtPcodeHeader.Text = $"P-Code: Scope {_currentFunctionName} ({_programModel.CurrentPcodeOps.Count} micro-ops)";
        }
        else
        {
            var ops = PcodeService.GeneratePcode(item);
            foreach (var op in ops) _programModel.CurrentPcodeOps.Add(op);
            if (TxtPcodeHeader != null)
                TxtPcodeHeader.Text = $"P-Code: {item.Instruction} {item.Operands} @ 0x{item.Address} ({ops.Count} ops)";
        }
    }

    private void BtnRefreshPcode_Click(object sender, RoutedEventArgs e)
    {
        if (LvListing.SelectedItem is ListingItem item)
        {
            UpdatePcode(item);
        }
    }

    private void ChkPcodeFunction_Changed(object sender, RoutedEventArgs e)
    {
        if (LvListing.SelectedItem is ListingItem item)
        {
            UpdatePcode(item);
        }
    }

    private void UpdateCallTree()
    {
        if (string.IsNullOrEmpty(_currentFunctionName) || TxtCallTreeScope == null) return;
        TxtCallTreeScope.Text = $"Scope: {_currentFunctionName} @ 0x{_currentAddress}";

        ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out ulong funcAddr);
        var (incoming, outgoing) = CallTreeService.BuildCallTree(_programModel, _currentFunctionName, funcAddr);

        _programModel.IncomingCalls.Clear();
        foreach (var inc in incoming) _programModel.IncomingCalls.Add(inc);

        _programModel.OutgoingCalls.Clear();
        foreach (var o in outgoing) _programModel.OutgoingCalls.Add(o);
    }

    private void BtnRefreshCallTree_Click(object sender, RoutedEventArgs e)
    {
        UpdateCallTree();
    }

    private void TreeCallTree_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is TreeView tv && tv.SelectedItem is CallTreeNode node)
        {
            if (node.CallSiteAddress != 0)
            {
                JumpToAddress($"{node.CallSiteAddress:X8}");
            }
            else if (node.Address != 0)
            {
                JumpToAddress($"{node.Address:X8}");
            }
        }
    }

    private void MenuShowCallTree_Click(object sender, RoutedEventArgs e)
    {
        if (TreeSymbols.SelectedItem is SymbolNode symNode && !string.IsNullOrEmpty(symNode.Address))
        {
            _currentFunctionName = symNode.Name;
            _currentAddress = symNode.Address;
            UpdateCallTree();
            JumpToAddress(symNode.Address);
        }
        else if (LvListing.SelectedItem is ListingItem item)
        {
            UpdateCallTree();
        }
    }

    private void MenuSetEquate_Click(object sender, RoutedEventArgs e)
    {
        SetEquate();
    }

    private void SetEquate()
    {
        if (LvListing.SelectedItem is not ListingItem item)
        {
            MessageBox.Show("Please select an instruction in the Listing to set an equate.", "Set Equate", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        ulong addr = 0;
        ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out addr);

        // Find candidate numbers in operands
        ulong val = 0;
        string ops = item.Operands;
        var parts = ops.Split(new[] { ' ', ',', '[', ']', '+', '-' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var p in parts)
        {
            if (p.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(p.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out ulong hVal))
            {
                val = hVal;
                break;
            }
            if (ulong.TryParse(p, out ulong dVal))
            {
                val = dVal;
                break;
            }
        }

        var dlg = new SetEquateDialog(addr, item.Instruction, item.Operands, val);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true && !string.IsNullOrEmpty(dlg.SelectedEquateName))
        {
            EquateService.ApplyEquate(_programModel, addr, dlg.SelectedEquateName, dlg.TargetValue, dlg.SelectedCategory);
            LvEquates.ItemsSource = null;
            LvEquates.ItemsSource = _programModel.Equates;
            TxtEquateCount.Text = $"{_programModel.Equates.Count} equate(s) defined";
            Log($"[Equate] Applied equate '{dlg.SelectedEquateName}' (0x{dlg.TargetValue:X}) at 0x{addr:X8}");
            DecompileCurrentFunction();
        }
    }

    private void BtnRemoveEquate_Click(object sender, RoutedEventArgs e)
    {
        if (LvEquates.SelectedItem is EquateModel eq && eq.ReferenceAddresses.Count > 0)
        {
            ulong addr = eq.ReferenceAddresses.First();
            EquateService.RemoveEquate(_programModel, addr);
            LvEquates.ItemsSource = null;
            LvEquates.ItemsSource = _programModel.Equates;
            TxtEquateCount.Text = $"{_programModel.Equates.Count} equate(s) defined";
            Log($"[Equate] Removed equate '{eq.Name}' from 0x{addr:X8}");
            DecompileCurrentFunction();
        }
    }

    private void LvEquates_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (LvEquates.SelectedItem is EquateModel eq && eq.ReferenceAddresses.Count > 0)
        {
            JumpToAddress($"{eq.ReferenceAddresses[0]:X8}");
        }
    }

    private void MenuMemoryMap_Click(object sender, RoutedEventArgs e)
    {
        var win = new MemoryMapWindow(_programModel, addr => JumpToAddress(addr), msg => Log(msg));
        win.Owner = this;
        win.Show();
    }

    private void MenuFunctionComparison_Click(object sender, RoutedEventArgs e)
    {
        var win = new FunctionComparisonWindow(_programModel, addr => JumpToAddress(addr), _currentFunctionName);
        win.Owner = this;
        win.Show();
    }

    private void MenuCompareFunction_Click(object sender, RoutedEventArgs e)
    {
        string? targetFunc = null;
        if (TreeSymbols.SelectedItem is SymbolNode sym)
        {
            targetFunc = sym.Name;
        }
        var win = new FunctionComparisonWindow(_programModel, addr => JumpToAddress(addr), _currentFunctionName, targetFunc);
        win.Owner = this;
        win.Show();
    }

    // =========================================================================
    // Tier 2 Enhancements: CParser, Entropy, Demangler, PDB, Flow Arrow, Roslyn Scripting
    // =========================================================================

    private void MenuParseCSource_Click(object sender, RoutedEventArgs e)
    {
        OpenCParser();
    }

    private void OpenCParser()
    {
        var dlg = new CParserDialog(_programModel, msg => Log(msg));
        dlg.Owner = this;
        if (dlg.ShowDialog() == true)
        {
            TreeDataTypes.ItemsSource = null;
            TreeDataTypes.ItemsSource = _programModel.DataTypeCategories;
            Log("[CParser] Data types updated in Data Type Manager tree.");
        }
    }

    private void MenuEntropyOverview_Click(object sender, RoutedEventArgs e)
    {
        var win = new EntropyWindow(_programModel, addr => JumpToAddress(addr));
        win.Owner = this;
        win.Show();
    }

    private void MenuPdbSymbol_Click(object sender, RoutedEventArgs e)
    {
        var win = new PdbSymbolWindow(_programModel, addr => JumpToAddress(addr), msg => Log(msg));
        win.Owner = this;
        win.Show();
    }

    private void MenuDemangleAllSymbols_Click(object sender, RoutedEventArgs e)
    {
        int count = DemanglerService.DemangleAllProgramSymbols(_programModel);
        Log($"[Demangler] Scanned and demangled {count} symbol(s) in program.");
        MessageBox.Show($"Demangled {count} C++ decorated symbol(s) in program listing!", "Demangler", MessageBoxButton.OK, MessageBoxImage.Information);
        DecompileCurrentFunction();
    }

    private void MenuUpdateFlowArrows_Click(object sender, RoutedEventArgs e)
    {
        FlowArrowService.UpdateFlowArrows(_programModel);
        LvListing.Items.Refresh();
        Log("[FlowArrows] Updated execution flow arrows across listing.");
    }

    private void MenuScriptManager_Click(object sender, RoutedEventArgs e)
    {
        OpenScriptManager();
    }

    private void OpenScriptManager()
    {
        ulong.TryParse(_currentAddress, System.Globalization.NumberStyles.HexNumber, null, out ulong curAddr);
        var win = new ScriptManagerWindow(_programModel, addr => JumpToAddress(addr), msg => Log(msg), curAddr, _currentFunctionName);
        win.Owner = this;
        win.Show();
    }

    private void MenuModifyFallthrough_Click(object sender, RoutedEventArgs e)
    {
        ModifyFallthrough();
    }

    private void ModifyFallthrough()
    {
        if (LvListing.SelectedItem is not ListingItem item)
        {
            MessageBox.Show("Please select an instruction in the Listing to modify fallthrough.", "Modify Fallthrough", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        ulong.TryParse(item.Address, System.Globalization.NumberStyles.HexNumber, null, out ulong addr);
        int idx = _programModel.ListingLines.IndexOf(item);
        ulong defaultNext = addr + 4;
        if (idx >= 0 && idx < _programModel.ListingLines.Count - 1)
        {
            if (ulong.TryParse(_programModel.ListingLines[idx + 1].Address, System.Globalization.NumberStyles.HexNumber, null, out ulong nextAddr))
            {
                defaultNext = nextAddr;
            }
        }

        ulong? currentOverride = item.FallthroughOverrideAddress;
        var dlg = new ModifyFallthroughDialog(addr, item.Instruction, item.Operands, defaultNext, currentOverride);
        dlg.Owner = this;
        if (dlg.ShowDialog() == true)
        {
            if (dlg.SelectedOverride.HasValue && dlg.SelectedOverride.Value == defaultNext)
            {
                FlowArrowService.ClearFallthroughOverride(_programModel, addr);
                Log($"[Fallthrough] Reset fallthrough at 0x{addr:X8} to default (0x{defaultNext:X8})");
            }
            else
            {
                FlowArrowService.SetFallthroughOverride(_programModel, addr, dlg.SelectedOverride);
                if (dlg.SelectedOverride.HasValue)
                {
                    Log($"[Fallthrough] Overrode fallthrough at 0x{addr:X8} -> 0x{dlg.SelectedOverride.Value:X8}");
                }
                else
                {
                    Log($"[Fallthrough] Set No Fallthrough at 0x{addr:X8}");
                }
            }
            LvListing.Items.Refresh();
        }
    }
}
