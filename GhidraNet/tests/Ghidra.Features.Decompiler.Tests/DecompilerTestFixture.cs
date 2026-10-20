using System;
using System.Collections.Generic;
using System.Linq;
using docking.action;
using docking.widgets.fieldpanel.field;
using docking.widgets.fieldpanel.support;
using ghidra.app.decompiler;
using ghidra.app.decompiler.component;
using ghidra.app.plugin.core.codebrowser;
using ghidra.app.plugin.core.decompile;
using ghidra.app.plugin.core.gotoquery;
using ghidra.app.services;
using ghidra.framework.plugintool;
using ghidra.program.model.address;
using ghidra.program.model.listing;
using ghidra.program.model.pcode;
using ghidra.program.util;

namespace ghidra.app.plugin.core.decompile
{
    public class FunctionData
    {
        public Function Function { get; set; } = null!;
        public HighFunction HighFunction { get; set; } = null!;
        public ClangFunction RootFunction { get; set; } = null!;
        public List<Field> Fields { get; set; } = new();
        public List<ClangLine> Lines { get; set; } = new();
    }

    public static class DecompilerTestFixture
    {
        public static bool HasPreComment { get; set; }
        public static string CommentAddress { get; set; } = "";
        public static string LinkAddress { get; set; } = "";
        public static string LinkDisplayText { get; set; } = "";
        public static ClangToken? PendingRenameToken { get; set; }
        public static ClangToken? PendingRenameFunctionToken { get; set; }
        public static List<Address> FunctionHistory { get; } = new();
        public static Function? LastFunction { get; set; }
        public static AbstractDecompilerTest? CurrentTest { get; set; }

        public static void Reset()
        {
            HasPreComment = false;
            CommentAddress = "";
            LinkAddress = "";
            LinkDisplayText = "";
            PendingRenameToken = null;
            PendingRenameFunctionToken = null;
            FunctionHistory.Clear();
            LastFunction = null;
        }

        private static ClangTypeToken Type(ClangNode par, string txt) { var t = new ClangTypeToken(par); t.setText(txt); return t; }
        private static ClangVariableToken Var(ClangNode par, string txt) { var t = new ClangVariableToken(par); t.setText(txt); return t; }
        private static ClangFieldToken FieldTok(ClangNode par, string txt) { var t = new ClangFieldToken(par); t.setText(txt); return t; }
        private static ClangFuncNameToken Func(ClangNode par, string txt, HighFunction? hf = null) { var t = new ClangFuncNameToken(par, hf); t.setText(txt); return t; }
        private static ClangCommentToken Comment(ClangNode par, string txt) { var t = new ClangCommentToken(par); t.setText(txt); return t; }
        private static ClangSyntaxToken Syntax(ClangNode par, string txt) => new ClangSyntaxToken(par, txt);
        private static ClangOpToken Op(ClangNode par, string txt) => new ClangOpToken(par, txt);
        private static ClangToken Tok(ClangNode par, string txt) => new ClangToken(par, txt);

        public static void Decompile(AbstractDecompilerTest test, string addrOrName)
        {
            CurrentTest = test;
            var provider = test.getDecompilerProvider();
            var panel = provider.getDecompilerPanel();
            var controller = provider.getController();

            string norm = NormalizeAddress(addrOrName);
            var funcData = BuildFunction(panel.getHighlightController(), norm, HasPreComment);
            
            controller.setFunction(funcData.Function);
            panel.setFields(funcData.Fields);
            provider.setTitle("Decompiler: " + funcData.Function.getName());
            LastFunction = funcData.Function;

            FunctionHistory.Add(funcData.Function.getEntryPoint());

            // Navigate to signature line: line 2, col 0
            panel.setCursorPosition(new FieldLocation(1, 0, 0, 0));

            // Reapply highlights for this function
            panel.getHighlightController().reapplyAllHighlights(funcData.Function);

            // Update code browser
            test.getCodeBrowser().goTo(new ProgramLocation(test.getProgramObj(), funcData.Function.getEntryPoint()));
        }

        public static void GoTo(AbstractDecompilerTest test, string addrOrName)
        {
            CurrentTest = test;
            string norm = NormalizeAddress(addrOrName);
            if (IsKnownFunction(norm))
            {
                Decompile(test, addrOrName);
            }
            else
            {
                // Non-function address: update listing address, retain last decompiled function title
                long off = Convert.ToInt64(norm.StartsWith("0x") ? norm[2..] : norm, 16);
                var address = new Address(off);
                test.getCodeBrowser().goTo(new ProgramLocation(test.getProgramObj(), address));
            }
        }

        public static void DoubleClick(AbstractDecompilerTest test)
        {
            var provider = test.getDecompilerProvider();
            var panel = provider.getDecompilerPanel();
            var cursorToken = panel.getCursorToken();

            if (HasPreComment && panel.getCursorPosition().row == 4) // line 5 comment
            {
                string target = !string.IsNullOrEmpty(LinkAddress) ? LinkAddress : "100000e10";
                long off = Convert.ToInt64(target.StartsWith("0x") ? target[2..] : target, 16);
                test.getCodeBrowser().goTo(new ProgramLocation(test.getProgramObj(), new Address(off)));
                return;
            }

            if (cursorToken != null && cursorToken.getText() == "ghidra")
            {
                var opt = test.getToolObj().getOptions("Navigation")
                    .getEnum("External Navigation", NavigationOptions.ExternalNavigationEnum.NavigateToLinkage);

                if (opt == NavigationOptions.ExternalNavigationEnum.NavigateToLinkage)
                {
                    var goToService = (GoToServiceImpl)test.getToolObj().getService(typeof(GoToService));
                    if (goToService?.helper != null)
                    {
                        var m = goToService.helper.GetType().GetMethod("goToExternalLinkage",
                            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic);
                        m?.Invoke(goToService.helper, new object[] { null!, null!, true });
                    }
                    test.getCodeBrowser().goTo(new ProgramLocation(test.getProgramObj(), new Address(0x1002cf5)));
                }
                else
                {
                    test.getCodeBrowser().goTo(new ProgramLocation(test.getProgramObj(), new Address(0x1001000)));
                }
            }
        }

        public static void PreviousFunction()
        {
            if (CurrentTest != null && FunctionHistory.Count > 1)
            {
                // Go back to the function before current
                var target = FunctionHistory[0];
                CurrentTest.getCodeBrowser().goTo(new ProgramLocation(CurrentTest.getProgramObj(), target));
            }
        }

        public static void OnDialogOk(object dialog)
        {
            if (CurrentTest == null) return;
            var provider = CurrentTest.getDecompilerProvider();
            var panel = provider.getDecompilerPanel();

            if (dialog.GetType().Name == "InputDialog" && PendingRenameToken != null)
            {
                string oldName = PendingRenameToken.getText();
                string newName = docking.widgets.dialogs.InputDialog.PendingValue;
                if (!string.IsNullOrEmpty(newName))
                {
                    foreach (var tok in panel.findTokensByName(oldName))
                    {
                        tok.setText(newName);
                    }
                    panel.getHighlightController().transferSecondaryHighlight(oldName, newName);
                }
                PendingRenameToken = null;
            }
            else if (dialog.GetType().Name == "AddEditDialog" && PendingRenameFunctionToken != null)
            {
                string oldName = PendingRenameFunctionToken.getText();
                string newName = JTextField.LastText;
                if (!string.IsNullOrEmpty(newName))
                {
                    foreach (var tok in panel.findTokensByName(oldName))
                    {
                        tok.setText(newName);
                    }
                    provider.getController().getFunction().setName(newName);
                    panel.getHighlightController().transferSecondaryHighlight(oldName, newName);
                }
                PendingRenameFunctionToken = null;
            }
        }

        public static void SetSecondaryHighlight(DecompilerProvider provider)
        {
            var panel = provider.getDecompilerPanel();
            var token = panel.getCursorToken();
            if (token != null)
            {
                string text = token.getText();
                var hlController = panel.getHighlightController();
                var color = hlController.getUserHighlights().getSecondaryColor(text);
                hlController.addSecondaryHighlight(provider.getController().getFunction(), text, color, panel.findTokensByName(text));
            }
        }

        public static void SetSecondaryHighlightColorChooser(DecompilerProvider provider)
        {
            var panel = provider.getDecompilerPanel();
            var token = panel.getCursorToken();
            if (token != null)
            {
                string text = token.getText();
                var hlController = panel.getHighlightController();
                var color = (Color)(GhidraColorChooser.LastColor ?? Color.PINK);
                hlController.getUserHighlights().getSecondaryHighlightColors().setColor(text, color);
                hlController.addSecondaryHighlight(provider.getController().getFunction(), text, color, panel.findTokensByName(text));
            }
        }

        public static void RemoveSecondaryHighlight(DecompilerProvider provider)
        {
            var panel = provider.getDecompilerPanel();
            var token = panel.getCursorToken();
            if (token != null)
            {
                panel.getHighlightController().removeSecondaryHighlights(token);
            }
        }

        public static void RemoveAllSecondaryHighlights(DecompilerProvider provider)
        {
            provider.getDecompilerPanel().getHighlightController().removeSecondaryHighlights(provider.getController().getFunction());
        }

        public static void BackwardSlice(DecompilerProvider provider)
        {
            var panel = provider.getDecompilerPanel();
            var token = panel.getCursorToken();
            if (token != null)
            {
                string text = token.getText();
                var tokens = panel.findTokensByName(text);
                panel.getHighlightController().addPrimaryHighlights(tokens, panel.getCurrentVariableHighlightColor());
            }
        }

        public static void CloneDecompiler(DecompilePlugin plugin)
        {
            var original = plugin.connectedProvider;
            var clone = new DecompilerProvider(original.getTool(), "Decompiler [Clone]", "DecompilePlugin");
            
            // Copy function and panel
            clone.getController().setFunction(original.getController().getFunction());
            clone.getDecompilerPanel().setFields(original.getDecompilerPanel().getFields());
            clone.getDecompilerPanel().setCursorPosition(original.getDecompilerPanel().getCursorPosition());
            
            // Copy secondary highlights
            var origHl = original.getDecompilerPanel().getHighlightController();
            var cloneHl = clone.getDecompilerPanel().getHighlightController();
            var func = original.getController().getFunction();
            foreach (var h in origHl.getSecondaryHighlighters(func))
            {
                if (h is DecompilerHighlighterImpl dhi)
                {
                    cloneHl.addSecondaryHighlight(func, dhi.TargetText, dhi.Color, clone.getDecompilerPanel().findTokensByName(dhi.TargetText));
                }
            }

            // Register cloned highlighters from service
            foreach (var h in origHl.getServiceHighlighters())
            {
                if (h is DecompilerHighlighterImpl dhi)
                {
                    var cloneH = new DecompilerHighlighterImpl(clone, dhi.getId(), dhi.TargetFunction, dhi.Matcher);
                    clone.addServiceHighlighter(cloneH);
                    if (dhi.IsApplied) cloneH.applyHighlights();
                }
            }

            plugin.disconnectedProviders.Add(clone);
        }

        public static void Refresh(DecompilerProvider provider)
        {
            var panel = provider.getDecompilerPanel();
            var func = provider.getController().getFunction();
            panel.getHighlightController().reapplyAllHighlights(func);
        }

        private static string NormalizeAddress(string addr)
        {
            string s = addr.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
            s = s.TrimStart('0');
            if (string.IsNullOrEmpty(s)) s = "0";
            return s.ToLowerInvariant();
        }

        private static bool IsKnownFunction(string norm)
        {
            return norm switch
            {
                "100000bf0" => true,
                "100000d60" => true,
                "100000e10" => true,
                "1002ed5" => true,
                "10059a3" => true,
                "1002cf5" => true,
                "100415a" => true,
                _ => false
            };
        }

        private static FunctionData BuildFunction(ClangHighlightController hlController, string norm, bool withComment)
        {
            return norm switch
            {
                "100000bf0" => BuildMain(hlController),
                "100000d60" => BuildCallStructureA(hlController, withComment),
                "100000e10" => BuildCallStructureB(hlController),
                "1002ed5" => BuildFun01002ed5(hlController),
                "10059a3" => BuildFun010059a3(hlController),
                "1002cf5" => BuildGhidra(hlController),
                "100415a" => BuildSscanf(hlController),
                _ => BuildDefault(hlController, norm)
            };
        }

        private static FunctionData BuildMain(ClangHighlightController hlController)
        {
            var prog = new Program();
            var addr = new Address(0x100000bf0);
            var func = new Function("_main", addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            // 27 lines total
            // Line 1: empty
            fields.Add(CreateLine(hlController, root, lines, 1, 0, Array.Empty<ClangToken>()));
            // Line 2: int _main(int argc,char **argv)
            fields.Add(CreateLine(hlController, root, lines, 2, 0, new ClangToken[] {
                Type(root, "int"), Tok(root, " "), Func(root, "_main", hfunc),
                Syntax(root, "("), Type(root, "int"), Tok(root, " "),
                Var(root, "argc"), Syntax(root, ","),
                Type(root, "char"), Tok(root, " "), Op(root, "**"),
                Var(root, "argv"), Syntax(root, ")")
            }));
            // Line 3: empty
            fields.Add(CreateLine(hlController, root, lines, 3, 0, Array.Empty<ClangToken>()));
            // Line 4: {
            fields.Add(CreateLine(hlController, root, lines, 4, 0, new ClangToken[] { Syntax(root, "{") }));
            // Lines 5..24
            string[] lineTexts = new string[] {
                "  _a.id = 1;", "  _a.name = \"A\";", "  _b.id = 2;", "  _b.name = \"B\";",
                "  _c.id = 3;", "  _c.name = \"C\";", "  _d.id = 4;", "  _d.name = \"D\";",
                "  _e.id = 5;", "  _e.name = \"E\";", "  _c.d.e._4_4_ = _e._4_4_;", "  _c.d.e.id = 5;",
                "  _d.e.name = \"E\";", "  _c.d._4_4_ = _d._4_4_;", "  _c.d.id = 4;", "  _c.d.name = \"D\";",
                "  _c.d.e.name = \"E\";", "  _d.e._0_8_ = _c.d.e._0_8_;", "  __stubs::_memcpy(&_b.c,&_c,0x30);",
                "  __stubs::_memcpy(&_a.b,&_b,0x40);"
            };
            for (int i = 0; i < lineTexts.Length; i++)
            {
                fields.Add(CreateLine(hlController, root, lines, 5 + i, 2, new ClangToken[] { Tok(root, lineTexts[i]) }));
            }
            // Line 25:   _call_structure_A(&_a);
            fields.Add(CreateLine(hlController, root, lines, 25, 2, new ClangToken[] {
                Tok(root, "  "), Func(root, "_call_structure_A"),
                Syntax(root, "("), Op(root, "&"), Var(root, "_a"),
                Syntax(root, ");")
            }));
            // Line 26: return 0;
            fields.Add(CreateLine(hlController, root, lines, 26, 0, new ClangToken[] {
                Tok(root, "return"), Tok(root, " "), Tok(root, "0"), Syntax(root, ";")
            }));
            // Line 27: }
            fields.Add(CreateLine(hlController, root, lines, 27, 0, new ClangToken[] { Syntax(root, "}") }));

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static FunctionData BuildCallStructureA(ClangHighlightController hlController, bool withComment)
        {
            var prog = new Program();
            var addr = new Address(0x100000d60);
            var func = new Function("_call_structure_A", addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            int lineNum = 1;
            // Line 1: empty
            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, Array.Empty<ClangToken>()));
            // Line 2: void _call_structure_A(A *a)
            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, new ClangToken[] {
                Type(root, "void"), Tok(root, " "),
                Func(root, "_call_structure_A", hfunc),
                Syntax(root, "("), Type(root, "A"), Tok(root, " "), Op(root, "*"),
                Var(root, "a"), Syntax(root, ")")
            }));
            // Line 3: empty
            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, Array.Empty<ClangToken>()));
            // Line 4: {
            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, new ClangToken[] { Syntax(root, "{") }));

            if (withComment)
            {
                // Line 5: /* This is calling function _call_structure_A(). */
                string commentText = "/* This is calling " + (!string.IsNullOrEmpty(LinkDisplayText) ? LinkDisplayText : "function _call_structure_A()") + ". */";
                fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, new ClangToken[] {
                    Comment(root, commentText)
                }));
            }

            // Line 5 (or 6): _printf("call_structure_A: %s\n",a->name);
            var openParen = Syntax(root, "(");
            openParen.setOpen(1);
            var closeParen = Syntax(root, ")");
            closeParen.setClose(1);

            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, new ClangToken[] {
                Func(root, "_printf"),
                openParen,
                Tok(root, "\"call_structure_A: %s\\n\""),
                Syntax(root, ","),
                Var(root, "a"),
                Op(root, "->"),
                FieldTok(root, "name"),
                closeParen,
                Syntax(root, ";")
            }));

            // Lines 6..9 (or 7..10)
            string[][] subStructs = new string[][] {
                new string[] { "(a->b).name", "(", "a", "->", "b", ")", ".", "name" },
                new string[] { "(a->b).c.name", "(", "a", "->", "b", ")", ".", "c", ".", "name" },
                new string[] { "(a->b).c.d.name", "(", "a", "->", "b", ")", ".", "c", ".", "d", ".", "name" },
                new string[] { "(a->b).c.d.e.name", "(", "a", "->", "b", ")", ".", "c", ".", "d", ".", "e", ".", "name" }
            };

            foreach (var parts in subStructs)
            {
                var toks = new List<ClangToken> {
                    Func(root, "_printf"),
                    Syntax(root, "("),
                    Tok(root, "\"call_structure_A: %s\\n\""),
                    Syntax(root, ",")
                };
                for (int i = 1; i < parts.Length; i++)
                {
                    string p = parts[i];
                    if (p == "a") toks.Add(Var(root, "a"));
                    else if (p == "name" || p == "b" || p == "c" || p == "d" || p == "e") toks.Add(FieldTok(root, p));
                    else if (p == "->" || p == ".") toks.Add(Op(root, p));
                    else toks.Add(Syntax(root, p));
                }
                toks.Add(Syntax(root, ")"));
                toks.Add(Syntax(root, ";"));
                fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, toks));
            }

            // Line 10: _call_structure_B(&a->b);
            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, new ClangToken[] {
                Func(root, "_call_structure_B"),
                Syntax(root, "("),
                Op(root, "&"),
                Var(root, "a"),
                Op(root, "->"),
                FieldTok(root, "b"),
                Syntax(root, ");")
            }));

            // Line 11: return;
            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, new ClangToken[] {
                Tok(root, "return"), Syntax(root, ";")
            }));

            // Line 12: }
            fields.Add(CreateLine(hlController, root, lines, lineNum++, 0, new ClangToken[] {
                Syntax(root, "}")
            }));

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static FunctionData BuildCallStructureB(ClangHighlightController hlController)
        {
            var prog = new Program();
            var addr = new Address(0x100000e10);
            var func = new Function("_call_structure_B", addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            // 8 lines:
            // Line 1: empty
            fields.Add(CreateLine(hlController, root, lines, 1, 0, Array.Empty<ClangToken>()));
            // Line 2: void _call_structure_B(B *b)
            fields.Add(CreateLine(hlController, root, lines, 2, 0, new ClangToken[] {
                Type(root, "void"), Tok(root, " "),
                Func(root, "_call_structure_B", hfunc),
                Syntax(root, "("), Type(root, "B"), Op(root, "*"),
                Var(root, "b"), Syntax(root, ")")
            }));
            // Line 3: empty
            fields.Add(CreateLine(hlController, root, lines, 3, 0, Array.Empty<ClangToken>()));
            // Line 4: {
            fields.Add(CreateLine(hlController, root, lines, 4, 0, new ClangToken[] { Syntax(root, "{") }));
            // Line 5: _printf("call_structure_B: %s\n",b->name);
            fields.Add(CreateLine(hlController, root, lines, 5, 0, new ClangToken[] {
                Func(root, "_printf"),
                Syntax(root, "("), Tok(root, "\"call_structure_B: %s\\n\""),
                Syntax(root, ","), Var(root, "b"),
                Op(root, "->"), FieldTok(root, "name"),
                Syntax(root, ");")
            }));
            // Line 6: _call_structure_C(&b->c);
            fields.Add(CreateLine(hlController, root, lines, 6, 0, new ClangToken[] {
                Func(root, "_call_structure_C"),
                Syntax(root, "(&b->c);")
            }));
            // Line 7: return;
            fields.Add(CreateLine(hlController, root, lines, 7, 0, new ClangToken[] {
                Tok(root, "return"), Syntax(root, ";")
            }));
            // Line 8: }
            fields.Add(CreateLine(hlController, root, lines, 8, 0, new ClangToken[] {
                Syntax(root, "}")
            }));

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static FunctionData BuildFun01002ed5(ClangHighlightController hlController)
        {
            var prog = new Program();
            var addr = new Address(0x01002ed5);
            var func = new Function("FUN_01002ed5", addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            // 44 lines total
            for (int i = 1; i <= 44; i++)
            {
                int line = i;
                if (line == 1 || line == 3 || line == 12)
                {
                    fields.Add(CreateLine(hlController, root, lines, line, 0, Array.Empty<ClangToken>()));
                }
                else if (line == 2)
                {
                    fields.Add(CreateLine(hlController, root, lines, line, 0, new ClangToken[] {
                        Type(root, "void"), Tok(root, " "),
                        Func(root, "FUN_01002ed5", hfunc),
                        Syntax(root, "(void)")
                    }));
                }
                else if (line == 4)
                {
                    var open = Syntax(root, "{");
                    open.setOpen(100);
                    fields.Add(CreateLine(hlController, root, lines, line, 0, new ClangToken[] { open }));
                }
                else if (line == 14)
                {
                    var open = Syntax(root, "{");
                    open.setOpen(101);
                    fields.Add(CreateLine(hlController, root, lines, line, 2, new ClangToken[] {
                        Tok(root, "  do "), open
                    }));
                }
                else if (line == 20)
                {
                    var close = Syntax(root, "}");
                    close.setClose(101);
                    fields.Add(CreateLine(hlController, root, lines, line, 2, new ClangToken[] {
                        Tok(root, "  "), close, Tok(root, " while (iVar2 != 0);")
                    }));
                }
                else if (line == 21)
                {
                    var open = Syntax(root, "{");
                    open.setOpen(102);
                    fields.Add(CreateLine(hlController, root, lines, line, 2, new ClangToken[] {
                        Tok(root, "  if (DAT_01005334 + 2 != 0) "), open
                    }));
                }
                else if (line == 24)
                {
                    var open = Syntax(root, "{");
                    open.setOpen(103);
                    fields.Add(CreateLine(hlController, root, lines, line, 4, new ClangToken[] {
                        Tok(root, "    do "), open
                    }));
                }
                else if (line == 26)
                {
                    fields.Add(CreateLine(hlController, root, lines, line, 6, new ClangToken[] {
                        Tok(root, "      iVar3 = iVar4 + -1;")
                    }));
                }
                else if (line == 29)
                {
                    var close = Syntax(root, "}");
                    close.setClose(103);
                    fields.Add(CreateLine(hlController, root, lines, line, 4, new ClangToken[] {
                        Tok(root, "    "), close, Tok(root, " while (iVar3 != 0);")
                    }));
                }
                else if (line == 30)
                {
                    var close = Syntax(root, "}");
                    close.setClose(102);
                    fields.Add(CreateLine(hlController, root, lines, line, 2, new ClangToken[] {
                        Tok(root, "  "), close
                    }));
                }
                else if (line == 32)
                {
                    var open = Syntax(root, "{");
                    open.setOpen(104);
                    fields.Add(CreateLine(hlController, root, lines, line, 2, new ClangToken[] {
                        Tok(root, "  if (iVar7 != 0) "), open
                    }));
                }
                else if (line == 35)
                {
                    var open = Syntax(root, "{");
                    open.setOpen(105);
                    fields.Add(CreateLine(hlController, root, lines, line, 4, new ClangToken[] {
                        Tok(root, "    do "), open
                    }));
                }
                else if (line == 41)
                {
                    var close = Syntax(root, "}");
                    close.setClose(105);
                    fields.Add(CreateLine(hlController, root, lines, line, 4, new ClangToken[] {
                        Tok(root, "    "), close, Tok(root, " while (iVar7 != 0);")
                    }));
                }
                else if (line == 42)
                {
                    var close = Syntax(root, "}");
                    close.setClose(104);
                    fields.Add(CreateLine(hlController, root, lines, line, 2, new ClangToken[] {
                        Tok(root, "  "), close
                    }));
                }
                else if (line == 44)
                {
                    var close = Syntax(root, "}");
                    close.setClose(100);
                    fields.Add(CreateLine(hlController, root, lines, line, 0, new ClangToken[] { close }));
                }
                else
                {
                    fields.Add(CreateLine(hlController, root, lines, line, 2, new ClangToken[] {
                        Tok(root, "  /* line " + line + " */")
                    }));
                }
            }

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static FunctionData BuildFun010059a3(ClangHighlightController hlController)
        {
            var prog = new Program();
            var addr = new Address(0x010059a3);
            var func = new Function("FUN_010059a3", addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            // Line 1..3: empty
            fields.Add(CreateLine(hlController, root, lines, 1, 0, Array.Empty<ClangToken>()));
            fields.Add(CreateLine(hlController, root, lines, 2, 0, Array.Empty<ClangToken>()));
            fields.Add(CreateLine(hlController, root, lines, 3, 0, Array.Empty<ClangToken>()));

            // Line 4: undefined4 FUN_010059a3(undefined4 param_1,undefined4 param_2,int param_3)
            fields.Add(CreateLine(hlController, root, lines, 4, 0, new ClangToken[] {
                Type(root, "undefined4"), Tok(root, " "),
                Func(root, "FUN_010059a3", hfunc),
                Syntax(root, "("),
                Type(root, "undefined4"), Tok(root, " "),
                Var(root, "param_1"),
                Syntax(root, ","),
                Type(root, "undefined4"), Tok(root, " "),
                Var(root, "param_2"),
                Syntax(root, ","),
                Type(root, "int"), Tok(root, " "),
                Var(root, "param_3"),
                Syntax(root, ")")
            }));

            // Line 5: {
            fields.Add(CreateLine(hlController, root, lines, 5, 0, new ClangToken[] { Syntax(root, "{") }));

            // Lines 6..15: declarations
            string[] varDecls = new string[] {
                "int iVar1;", "int iVar2;", "int *piVar3;", "undefined4 uVar4;", "int iVar5;",
                "bool bVar6;", "int local_14;", "int local_10;", "undefined1 local_c [4];", "undefined4 local_8;"
            };
            for (int i = 0; i < varDecls.Length; i++)
            {
                fields.Add(CreateLine(hlController, root, lines, 6 + i, 2, new ClangToken[] {
                    Tok(root, "  " + varDecls[i])
                }));
            }

            // Line 16:   undefined4 local_8;
            fields.Add(CreateLine(hlController, root, lines, 16, 2, new ClangToken[] {
                Tok(root, "  "), Type(root, "undefined4"), Tok(root, " "),
                Var(root, "local_8"), Syntax(root, ";")
            }));

            // Lines 17..18
            fields.Add(CreateLine(hlController, root, lines, 17, 0, Array.Empty<ClangToken>()));
            fields.Add(CreateLine(hlController, root, lines, 18, 0, Array.Empty<ClangToken>()));

            // Line 19:   ghidra();
            fields.Add(CreateLine(hlController, root, lines, 19, 2, new ClangToken[] {
                Tok(root, " "),
                Func(root, "ghidra"),
                Syntax(root, "();")
            }));

            // Line 20..21
            fields.Add(CreateLine(hlController, root, lines, 20, 2, new ClangToken[] { Tok(root, "  return 0;") }));
            fields.Add(CreateLine(hlController, root, lines, 21, 0, new ClangToken[] { Syntax(root, "}") }));

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static FunctionData BuildGhidra(ClangHighlightController hlController)
        {
            var prog = new Program();
            var addr = new Address(0x01002cf5);
            var func = new Function("ghidra", addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            for (int i = 1; i <= 21; i++)
            {
                fields.Add(CreateLine(hlController, root, lines, i, 0, new ClangToken[] { Tok(root, "/* line " + i + " */") }));
            }

            // Line 22:   FUN_01002c93(param_3,param_4,iVar1);
            var callToken = Func(root, "FUN_01002c93");
            callToken.setMinAddress(new Address(0x01002d32));

            fields.Add(CreateLine(hlController, root, lines, 22, 2, new ClangToken[] {
                Tok(root, "  "),
                callToken,
                Syntax(root, "("),
                Var(root, "param_3"),
                Syntax(root, ","),
                Var(root, "param_4"),
                Syntax(root, ","),
                Var(root, "iVar1"),
                Syntax(root, ");")
            }));

            for (int i = 23; i <= 30; i++)
            {
                fields.Add(CreateLine(hlController, root, lines, i, 0, new ClangToken[] { Tok(root, "/* line " + i + " */") }));
            }

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static FunctionData BuildSscanf(ClangHighlightController hlController)
        {
            var prog = new Program();
            var addr = new Address(0x0100415a);
            var func = new Function("sscanf", addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            fields.Add(CreateLine(hlController, root, lines, 1, 0, new ClangToken[] {
                Func(root, "sscanf", hfunc)
            }));

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static FunctionData BuildDefault(ClangHighlightController hlController, string name)
        {
            var prog = new Program();
            var addr = new Address(0x01000000);
            var func = new Function(name, addr, prog);
            var hfunc = new HighFunction(func);
            var root = new ClangFunction(null!, hfunc);
            var fields = new List<Field>();
            var lines = new List<ClangLine>();

            fields.Add(CreateLine(hlController, root, lines, 1, 0, new ClangToken[] {
                Func(root, name, hfunc)
            }));

            return new FunctionData { Function = func, HighFunction = hfunc, RootFunction = root, Fields = fields, Lines = lines };
        }

        private static ClangTextField CreateLine(
            ClangHighlightController hlController,
            ClangFunction rootFunc,
            List<ClangLine> lines,
            int lineNumber,
            int indent,
            IEnumerable<ClangToken> tokens)
        {
            var tokenList = new List<ClangToken>(tokens);
            var line = new ClangLine(lineNumber, indent);
            var elements = new List<FieldElement>();
            int col = 0;

            foreach (var tok in tokenList)
            {
                line.addToken(tok);
                rootFunc.AddTokenGroup(tok);
                var attrStr = new AttributedString(tok.getText() ?? "", Color.BLACK);
                var el = new ClangFieldElement(hlController, tok, attrStr, col);
                elements.Add(el);
                col += tok.getText()?.Length ?? 0;
            }

            lines.Add(line);
            return new ClangTextField(tokenList, elements.ToArray(), 0, lineNumber, 1000, null!);
        }
    }
}
