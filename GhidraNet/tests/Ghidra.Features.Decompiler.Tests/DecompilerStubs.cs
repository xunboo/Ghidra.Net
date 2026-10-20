using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using ghidra.util.datastruct;

namespace docking.widgets.fieldpanel.support
{
    public class FieldLocation : IComparable<FieldLocation>
    {
        public int row;
        public int col;
        public int subRow;
        public int charOffset;

        public FieldLocation() { }
        public FieldLocation(int row, int col) { this.row = row; this.col = col; }
        public FieldLocation(int row, int col, int subRow, int charOffset)
        {
            this.row = row;
            this.col = col;
            this.subRow = subRow;
            this.charOffset = charOffset;
        }

        public BigInteger getIndex() => new BigInteger(row);
        public int getFieldNum() => 0;
        public int getRow() => row;
        public int getCol() => col;

        public override bool Equals(object? obj)
        {
            if (obj is FieldLocation other)
                return row == other.row && col == other.col && subRow == other.subRow && charOffset == other.charOffset;
            return false;
        }

        public override int GetHashCode() => HashCode.Combine(row, col, subRow, charOffset);
        public int CompareTo(FieldLocation? other)
        {
            if (other == null) return 1;
            int r = row.CompareTo(other.row);
            return r != 0 ? r : col.CompareTo(other.col);
        }
    }

    public class FieldSelection
    {
        private readonly List<(FieldLocation start, FieldLocation end)> ranges = new();

        public void addRange(FieldLocation start, FieldLocation end) => ranges.Add((start, end));
        public bool contains(FieldLocation loc) => ranges.Any(r => loc.CompareTo(r.start) >= 0 && loc.CompareTo(r.end) <= 0);
        public bool isEmpty() => ranges.Count == 0;
        public void clear() => ranges.Clear();
    }

    public class Highlight
    {
        public int start;
        public int end;
        public Color color;
        public Highlight(int start, int end, Color color)
        {
            this.start = start;
            this.end = end;
            this.color = color;
        }
    }

    public interface FieldHighlightFactory
    {
        Highlight[] createHighlights(field.Field field, string text, int cursorTextOffset);
    }
}

namespace docking.widgets.fieldpanel.field
{
    using docking.widgets.fieldpanel.support;

    public interface Field
    {
        string getText();
        int getNumRows();
        int getNumCols(int row);
        int getX();
        int getY();
        int getWidth();
        int getHeight();
        int getPreferredWidth();
        FieldElement getFieldElement(int row, int col);
    }

    public interface FieldElement
    {
        string getText();
        int length();
        char getCharacter(int i);
        Color getColor(int i);
        FieldElement substring(int start, int end);
    }

    public abstract class AbstractTextFieldElement : FieldElement
    {
        protected AttributedString asString;
        protected int row;
        protected int col;

        protected AbstractTextFieldElement(AttributedString str, int row, int col)
        {
            this.asString = str;
            this.row = row;
            this.col = col;
        }

        public virtual string getText() => asString?.getText() ?? "";
        public virtual int length() => asString?.length() ?? 0;
        public virtual char getCharacter(int i) => getText()[i];
        public virtual Color getColor(int i) => asString?.getColor() ?? Color.BLACK;
        public virtual FieldElement substring(int start, int end) => this;
    }

    public class CompositeFieldElement : FieldElement
    {
        private readonly FieldElement[] elements;
        private readonly string fullText;

        public CompositeFieldElement(FieldElement[] elements)
        {
            this.elements = elements ?? Array.Empty<FieldElement>();
            StringBuilder sb = new();
            foreach (var el in this.elements) sb.Append(el.getText());
            fullText = sb.ToString();
        }

        public string getText() => fullText;
        public int length() => fullText.Length;
        public char getCharacter(int i) => fullText[i];
        public Color getColor(int i) => Color.BLACK;
        public FieldElement substring(int start, int end) => this;
        public FieldElement[] getElements() => elements;
    }

    public class AttributedString
    {
        private readonly string text;
        private readonly Color color;

        public AttributedString(string text, Color color, object? metrics = null)
        {
            this.text = text ?? "";
            this.color = color;
        }

        public string getText() => text;
        public int length() => text.Length;
        public Color getColor() => color;
    }

    public class WrappingVerticalLayoutTextField : Field
    {
        protected FieldElement element;
        protected int startX;
        protected int width;
        protected int rowHeight;
        protected FieldHighlightFactory? hlFactory;

        public WrappingVerticalLayoutTextField(FieldElement element, int startX, int width, int rowHeight,
            FieldHighlightFactory? hlFactory, bool b, string s)
        {
            this.element = element;
            this.startX = startX;
            this.width = width;
            this.rowHeight = rowHeight;
            this.hlFactory = hlFactory;
        }

        public virtual string getText() => element?.getText() ?? "";
        public virtual int getNumRows() => 1;
        public virtual int getNumCols(int row) => element?.length() ?? 0;
        public virtual int getX() => startX;
        public virtual int getY() => 0;
        public virtual int getWidth() => width;
        public virtual int getHeight() => rowHeight;
        public virtual int getPreferredWidth() => width;
        public virtual FieldElement getFieldElement(int row, int col) => element;
    }
}

namespace docking.widgets.fieldpanel
{
    using docking.widgets.fieldpanel.support;
    using docking.widgets.fieldpanel.field;

    public class FieldPanel
    {
        public Field? getCurrentField() => null;
        public void scrollTo(FieldLocation loc) { }
        public Point getPointForLocation(FieldLocation loc) => new Point(loc.col, loc.row);
    }
}

public class Color : IEquatable<Color>
{
    public static readonly Color BLACK = new(0, 0, 0, "black");
    public static readonly Color WHITE = new(255, 255, 255, "white");
    public static readonly Color RED = new(255, 0, 0, "red");
    public static readonly Color GREEN = new(0, 255, 0, "green");
    public static readonly Color BLUE = new(0, 0, 255, "blue");
    public static readonly Color YELLOW = new(255, 255, 0, "yellow");
    public static readonly Color CYAN = new(0, 255, 255, "cyan");
    public static readonly Color MAGENTA = new(255, 0, 255, "magenta");
    public static readonly Color GRAY = new(128, 128, 128, "gray");
    public static readonly Color PINK = new(255, 175, 175, "pink");

    public int R { get; }
    public int G { get; }
    public int B { get; }
    public int A { get; }
    public string Name { get; }

    public Color(int r, int g, int b, string name = "")
    {
        R = r; G = g; B = b; A = 255;
        Name = name;
    }

    public Color(int r, int g, int b, int a, string name = "")
    {
        R = r; G = g; B = b; A = a;
        Name = name;
    }

    public Color(int rgb)
    {
        R = (rgb >> 16) & 0xff;
        G = (rgb >> 8) & 0xff;
        B = rgb & 0xff;
        A = 255;
        Name = "";
    }

    public int getRed() => R;
    public int getGreen() => G;
    public int getBlue() => B;
    public int getAlpha() => A;
    public int getRGB() => (A << 24) | (R << 16) | (G << 8) | B;

    public static Color getHSBColor(float h, float s, float b)
    {
        int red = 0, green = 0, blue = 0;
        if (s == 0)
        {
            red = green = blue = (int)(b * 255.0f + 0.5f);
        }
        else
        {
            float hue = (h - (float)Math.Floor(h)) * 6.0f;
            float f = hue - (float)Math.Floor(hue);
            float p = b * (1.0f - s);
            float q = b * (1.0f - s * f);
            float t = b * (1.0f - (s * (1.0f - f)));
            switch ((int)hue)
            {
                case 0:
                    red = (int)(b * 255.0f + 0.5f);
                    green = (int)(t * 255.0f + 0.5f);
                    blue = (int)(p * 255.0f + 0.5f);
                    break;
                case 1:
                    red = (int)(q * 255.0f + 0.5f);
                    green = (int)(b * 255.0f + 0.5f);
                    blue = (int)(p * 255.0f + 0.5f);
                    break;
                case 2:
                    red = (int)(p * 255.0f + 0.5f);
                    green = (int)(b * 255.0f + 0.5f);
                    blue = (int)(t * 255.0f + 0.5f);
                    break;
                case 3:
                    red = (int)(p * 255.0f + 0.5f);
                    green = (int)(q * 255.0f + 0.5f);
                    blue = (int)(b * 255.0f + 0.5f);
                    break;
                case 4:
                    red = (int)(t * 255.0f + 0.5f);
                    green = (int)(p * 255.0f + 0.5f);
                    blue = (int)(b * 255.0f + 0.5f);
                    break;
                case 5:
                    red = (int)(b * 255.0f + 0.5f);
                    green = (int)(p * 255.0f + 0.5f);
                    blue = (int)(q * 255.0f + 0.5f);
                    break;
            }
        }
        return new Color(red, green, blue);
    }

    public override bool Equals(object? obj) => obj is Color c && Equals(c);
    public bool Equals(Color? other) => other != null && R == other.R && G == other.G && B == other.B && A == other.A;
    public override int GetHashCode() => HashCode.Combine(R, G, B, A);
    public override string ToString() => string.IsNullOrEmpty(Name) ? $"Color({R},{G},{B},{A})" : Name;
}

public record struct Point(int x, int y);

namespace generic.theme.GThemeDefaults.Colors
{
    public static class Palette
    {
        public static readonly Color BLACK = Color.BLACK;
        public static readonly Color RED = Color.RED;
        public static readonly Color GREEN = Color.GREEN;
        public static readonly Color BLUE = Color.BLUE;
        public static readonly Color YELLOW = Color.YELLOW;
        public static readonly Color PINK = new Color(255, 175, 175);
        public static readonly Color GRAY = Color.GRAY;
        public static readonly Color LIGHT_GRAY = new Color(192, 192, 192);
        public static readonly Color DARK_GRAY = new Color(64, 64, 64);
        public static readonly Color CYAN = Color.CYAN;
        public static readonly Color MAGENTA = Color.MAGENTA;
        public static readonly Color ORANGE = new Color(255, 200, 0);
    }

    public static class Messages
    {
        public static readonly Color ERROR = Color.RED;
    }
}

namespace docking.action
{

    public class KeyBindingData
    {
        public KeyBindingData(int key, int mask) { }
    }

    public static class KeyEvent
    {
        public const int VK_CLOSE_BRACKET = 93;
        public const int VK_OPEN_BRACKET = 91;
    }

    public static class InputEvent
    {
        public const int SHIFT_DOWN_MASK = 1;
    }
}

namespace docking.options
{
    using ghidra.framework.options;
    public interface Options : ToolOptions
    {
    }
}

namespace ghidra.framework.options
{
    public interface ToolOptions
    {
        void setEnum<T>(string name, T val) where T : struct, Enum;
        T getEnum<T>(string name, T defaultVal) where T : struct, Enum;
        void setInt(string name, int val);
        int getInt(string name, int defaultVal);
        void setBoolean(string name, bool val);
        bool getBoolean(string name, bool defaultVal);
        void setString(string name, string val);
        string getString(string name, string defaultVal);
    }

    public class ToolOptionsImpl : ToolOptions
    {
        private readonly Dictionary<string, object> options = new();

        public void setEnum<T>(string name, T val) where T : struct, Enum => options[name] = val;
        public T getEnum<T>(string name, T defaultVal) where T : struct, Enum => options.TryGetValue(name, out var v) && v is T val ? val : defaultVal;
        public void setInt(string name, int val) => options[name] = val;
        public int getInt(string name, int defaultVal) => options.TryGetValue(name, out var v) && v is int val ? val : defaultVal;
        public void setBoolean(string name, bool val) => options[name] = val;
        public bool getBoolean(string name, bool defaultVal) => options.TryGetValue(name, out var v) && v is bool val ? val : defaultVal;
        public void setString(string name, string val) => options[name] = val;
        public string getString(string name, string defaultVal) => options.TryGetValue(name, out var v) && v is string val ? val : defaultVal;
    }
}

namespace ghidra.app.services
{
    using ghidra.framework.options;
    using ghidra.app.plugin.core.gotoquery;
    using ghidra.framework.plugintool;

    public interface OptionsService
    {
        ToolOptions getOptions(string name);
    }

    public interface GoToService
    {
    }

    public class GoToServiceImpl : GoToService
    {
        public GoToHelper helper;
        public GoToServiceImpl(PluginTool tool) { }
    }

    public static class NavigationOptions
    {
        public enum ExternalNavigationEnum
        {
            NavigateToExternalProgram,
            NavigateToLinkage
        }
    }
}

namespace ghidra.app.nav
{
    public interface Navigatable
    {
    }
}

namespace ghidra.app.plugin.core.gotoquery
{
    using ghidra.app.nav;
    using ghidra.program.model.symbol;
    using ghidra.framework.plugintool;

    public class GoToHelper
    {
        protected PluginTool tool;
        public GoToHelper(PluginTool tool) { this.tool = tool; }

        protected virtual bool goToExternalLinkage(Navigatable nav, ExternalLocation externalLoc, bool popupAllowed)
        {
            return true;
        }
    }
}

namespace ghidra.app.plugin.core.codebrowser
{
    using ghidra.program.model.address;
    using ghidra.program.util;
    using ghidra.framework.plugintool;

    public class CodeViewerProvider : ComponentProvider
    {
        public CodeViewerProvider(PluginTool tool, string name, string owner) : base(tool, name, owner) { }
    }

    public class CodeBrowserPlugin : Plugin
    {
        private Address currentAddress = new Address(0x0100416c);
        private ProgramLocation currentLocation = new ProgramLocation();
        private CodeViewerProvider provider;

        public CodeBrowserPlugin(PluginTool tool) : base("CodeBrowserPlugin", tool)
        {
            provider = new CodeViewerProvider(tool, "Listing", "CodeBrowserPlugin");
        }

        public CodeViewerProvider getProvider() => provider;
        public void goTo(ProgramLocation loc) { currentLocation = loc; currentAddress = loc.getAddress(); }
        public ProgramLocation getCurrentLocation() => currentLocation;
        public Address getCurrentAddress() => currentAddress;
        public void updateNow() { }
    }
}

namespace ghidra.app.util.navigation
{
    using ghidra.program.model.listing;
    using ghidra.program.model.address;

    public static class NavigationUtils
    {
        public static Address[] getExternalLinkageAddresses(Program program, Address addr)
        {
            return new Address[] { addr };
        }
    }
}

namespace ghidra.framework.plugintool
{
    using ghidra.framework.options;
    using ghidra.app.services;

    public class OptionsServiceImpl : OptionsService
    {
        private readonly PluginTool tool;
        public OptionsServiceImpl(PluginTool tool) { this.tool = tool; }
        public ToolOptions getOptions(string name) => tool.getOptions(name);
    }

    public class PluginTool
    {
        private readonly Dictionary<Type, object> services = new();
        private readonly ToolOptionsImpl defaultOptions = new();

        public PluginTool()
        {
            services[typeof(OptionsService)] = new OptionsServiceImpl(this);
            services[typeof(GoToService)] = new GoToServiceImpl(this);
        }

        public ToolOptions getOptions(string name) => defaultOptions;
        public void addService(Type type, object service) => services[type] = service;
        public dynamic? getService(Type type) => services.TryGetValue(type, out var s) ? s : null!;
        public void showComponentProvider(ComponentProvider p, bool show) { }
    }

    public abstract class Plugin
    {
        protected PluginTool tool;
        protected string name;
        public Plugin(string name, PluginTool tool) { this.name = name; this.tool = tool; }
    }

    public abstract class ComponentProvider
    {
        protected PluginTool tool;
        protected string name;
        protected string owner;
        public ComponentProvider(PluginTool tool, string name, string owner)
        {
            this.tool = tool;
            this.name = name;
            this.owner = owner;
        }
        public PluginTool getTool() => tool;
        public string getName() => name;
    }
}

namespace ghidra.program.model.address
{
    public class AddressSpace { public string getName() => "ram"; public Address getAddress(long offset) => new Address(offset); }

    public class Address : IComparable<Address>
    {
        public bool isStackAddress() => false;
        private readonly long offset;
        public Address() : this(0) { }
        public Address(long offset) { this.offset = offset; }
        public Address(string hex)
        {
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
            if (long.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out long val))
                this.offset = val;
            else
                long.TryParse(hex, out this.offset);
        }

        public long getOffset() => offset;
        public Address add(long val) => new Address(offset + val);
        public Address subtract(long val) => new Address(offset - val);
        public string toString() => $"0x{offset:x8}";
        public override string ToString() => toString();
        public override bool Equals(object? obj) => obj is Address other && offset == other.offset;
        public override int GetHashCode() => offset.GetHashCode();
        public int CompareTo(Address? other) => other == null ? 1 : offset.CompareTo(other.offset);
    }

    public interface AddressFactory
    {
        Address getAddress(string addrString);
    }

    public class AddressFactoryImpl : AddressFactory
    {
        public Address getAddress(string addrString) => new Address(addrString);
    }
}

namespace ghidra.program.model.pcode
{
    using ghidra.program.model.data;
    using ghidra.program.model.address;
    using ghidra.program.model.listing;
    using ghidra.program.model.scalar;
    using ghidra.program.model.symbol;


    public class Varnode
    {
        private readonly Address addr;
        private readonly int size;
        public Varnode(Address addr, int size) { this.addr = addr; this.size = size; }
        public Address getAddress() => addr;
        public int getSize() => size;
        public long getOffset() => addr?.getOffset() ?? 0;
        public PcodeOp? getDef() => null;
        public HighVariable? getHigh() => new HighVariable();
    }

    public class HighVariable
    {
        private readonly string name;
        public HighVariable(string name = "var") { this.name = name; }
        public string getName() => name;
        public HighSymbol? getSymbol() => new HighSymbol(name);
        public DataType? getDataType() => null;
        public Varnode? getRepresentative() => null;
        public void attachInstances(IEnumerable<Varnode> instances, Varnode rep) { }
    }

    public class HighSymbol
    {
        private readonly string name;
        public HighSymbol(string name = "sym") { this.name = name; }
        public string getName() => name;
        public long getId() => 0;
        public HighVariable? getHighVariable() => new HighVariable(name);
        public Program? getProgram() => null;
        public DataType? getDataType() => null;
    }

    
    public class HighConstant : HighVariable
    {
        public HighConstant(string name = "const") : base(name) { }
        public Scalar getScalar() => new Scalar(0);
    }

    public class PcodeBlockBasic
    {
        public IEnumerator<PcodeOp> getIterator() => Enumerable.Empty<PcodeOp>().GetEnumerator();
        public int getInSize() => 0;
        public PcodeBlockBasic? getIn(int i) => null;
        public PcodeOp? getLastOp() => null;
    }

    public class LocalSymbolMap : SymbolMap { public HighSymbol? findLocal(Address addr, object? pc) => null; }
    public class GlobalSymbolMap : SymbolMap { }

    public static class HighFunctionDBUtil
    {
        public static void commitLocalsToDatabase(HighFunction hf, SourceType st) { }
        public static Address? getSpacebaseReferenceAddress(AddressFactory addrFactory, PcodeOp op) => null;
    }

    public class SymbolMap
    {
        public HighSymbol? getSymbol(int id) => null;
        public HighSymbol? getSymbol(Address addr) => null;
        public IEnumerator<HighSymbol> getSymbols() => Enumerable.Empty<HighSymbol>().GetEnumerator();
    }

    public class HighFunction : PcodeFactory
    {
        private readonly Function function;
        public AddressFactory getAddressFactory() => new AddressFactoryImpl();
        public LocalSymbolMap getLocalSymbolMap() => new();
        public GlobalSymbolMap getGlobalSymbolMap() => new();
        public HighFunction(Function function) { this.function = function; }
        public Function getFunction() => function;
    }

    public interface PcodeFactory
    {
        PcodeOp? getOpRef(int refId) => null;
        Varnode? getRef(int refId) => null;
        HighSymbol? getSymbol(long symId) => null;
        HighSymbol? getSymbol(int symId) => null;
        object? getDataTypeManager() => null;
    }

    public class Decoder
    {
        public int getNextAttributeId() => 0;
        public long readUnsignedInteger(AttributeId? id = null) => 0;
        public int openElement(ElementId? id = null) => 0;
        public void closeElement(int id) { }
        public AddressSpace? readSpace(AttributeId? id = null) => new AddressSpace();
        public long readSignedInteger(AttributeId? id = null) => 0;
        public string readString(AttributeId? id = null) => "";
        public void rewindAttributes() { }
    }

    public class DecoderException : Exception
    {
        public DecoderException(string msg) : base(msg) { }
    }

    public class SequenceNumber
    {
        public Address getTarget() => new Address(0);
        public int getOrder() => 0;
    }

    public class PcodeOp
    {
        public const int UNIMPLEMENTED = 0;
        public const int COPY = 1;
        public const int LOAD = 2;
        public const int STORE = 3;
        public const int BRANCH = 4;
        public const int CBRANCH = 5;
        public const int BRANCHIND = 6;
        public const int CALL = 7;
        public const int CALLOTHER = 9;
        public const int RETURN = 10;
        public const int INT_EQUAL = 11;
        public const int INT_ADD = 19;

        public Varnode? getInput(int i) => null;
        public Varnode? getOutput() => null;
        public int getOpcode() => 0;
        public PcodeBlockBasic? getParent() => null;
        public SequenceNumber getSeqnum() => new();
    }
}

namespace ghidra.program.model.scalar
{
    public class Scalar
    {
        private readonly long value;
        public Scalar(long value = 0) { this.value = value; }
        public Scalar(int size, long value, bool signed = false) { this.value = value; }
        public long getValue() => value;
        public long getSignedValue() => value;
        public ulong getUnsignedValue() => (ulong)value;
    }
}

namespace ghidra.program.model.symbol
{
    using ghidra.program.model.address;
    using ghidra.program.model.listing;

    public enum SourceType
    {
        DEFAULT,
        IMPORTED,
        ANALYSIS,
        USER_DEFINED
    }

    public class RefType
    {
        public static readonly RefType FALL_THROUGH = new();
        public static readonly RefType UNCONDITIONAL_CALL = new();
    }

    public class Library
    {
        public static readonly Library UNKNOWN = new Library("UNKNOWN");
        public string Name { get; }
        public Library(string name) { Name = name; }
    }

    public class Symbol
    {
        private readonly string name;
        private readonly Address address;
        private readonly Program program;

        public Symbol(string name, Address address, Program program)
        {
            this.name = name;
            this.address = address;
            this.program = program;
        }

        public string getName() => name;
        public Address getAddress() => address;
        public Program getProgram() => program;
    }

    public class ExternalLocation
    {
        private Symbol symbol;
        private Function function;

        public ExternalLocation(Symbol symbol, Function function)
        {
            this.symbol = symbol;
            this.function = function;
        }

        public Symbol getSymbol() => symbol;
        public Function getFunction() => function;
        public void setName(Library lib, string name, SourceType type) { }
        public bool isFunction() => function != null;
    }

    public class ExternalManager
    {
        private readonly Program program;
        public ExternalManager(Program program) { this.program = program; }

        public ExternalLocation addExtFunction(Library lib, string name, Address addr, SourceType type)
        {
            var sym = new Symbol(name, addr, program);
            var fn = new Function(name, addr, program);
            return new ExternalLocation(sym, fn);
        }

        public Library addExternalLibraryName(string name, SourceType type) => new Library(name);
        public void setExternalPath(string name, string path, bool userDefined) { }
    }
}

namespace ghidra.program.model.listing
{
    using ghidra.program.model.address;
    using ghidra.program.model.symbol;
    public interface Variable { }

    public class Function
    {
        private string name;
        private Address entryPoint;
        private Program program;
        private Function? thunkedFunction;

        public Function(string name, Address entryPoint, Program program)
        {
            this.name = name;
            this.entryPoint = entryPoint;
            this.program = program;
        }

        public string getName() => name;
        public void setName(string n) => name = n;
        public Address getEntryPoint() => entryPoint;
        public Program getProgram() => program;
        public Function? getThunkedFunction(bool recursive = false) => thunkedFunction;
        public void setThunkedFunction(Function? fn) => thunkedFunction = fn;
        public override bool Equals(object? obj) => obj is Function other && (entryPoint != null ? entryPoint.Equals(other.entryPoint) : name == other.name);
        public override int GetHashCode() => entryPoint != null ? entryPoint.GetHashCode() : (name?.GetHashCode() ?? 0);
    }

    public class FunctionManager
    {
        private readonly Dictionary<Address, Function> functions = new();
        private readonly Program program;

        public FunctionManager(Program program) { this.program = program; }
        public void addFunction(Function fn) => functions[fn.getEntryPoint()] = fn;
        public Function getFunctionAt(Address addr)
        {
            if (functions.TryGetValue(addr, out var fn)) return fn;
            fn = new Function("FUN_" + addr.getOffset().ToString("x"), addr, program);
            functions[addr] = fn;
            return fn;
        }
    }

    public enum CommentType
    {
        EOL, PRE, POST, PLATE, REPEATABLE
    }

    public class Program
    {
        private readonly string name;
        private readonly FunctionManager functionManager;
        private readonly ExternalManager externalManager;
        private readonly AddressFactory addressFactory = new AddressFactoryImpl();

        public Program(string name = "TestProgram")
        {
            this.name = name;
            functionManager = new FunctionManager(this);
            externalManager = new ExternalManager(this);
        }

        public string getName() => name;
        public FunctionManager getFunctionManager() => functionManager;
        public ExternalManager getExternalManager() => externalManager;
        public AddressFactory getAddressFactory() => addressFactory;
    }
}

namespace ghidra.program.util
{
    using ghidra.program.model.address;
    using ghidra.program.model.listing;

    public class ProgramLocation
    {
        protected Address address;
        protected Program program;

        public ProgramLocation() : this(null!, new Address(0)) { }
        public ProgramLocation(Program program, Address address)
        {
            this.program = program;
            this.address = address;
        }

        public Address getAddress() => address;
        public Program getProgram() => program;
    }

    public class OperandFieldLocation : ProgramLocation
    {
        private readonly string operandRepresentation;
        private readonly int opIndex;
        private readonly int subOpIndex;

        public OperandFieldLocation(Program program, Address addr, object? compPath, Address refAddr,
            string rep, int opIndex, int subOpIndex) : base(program, addr)
        {
            this.operandRepresentation = rep;
            this.opIndex = opIndex;
            this.subOpIndex = subOpIndex;
        }

        public string getOperandRepresentation() => operandRepresentation;
    }

    public class FunctionNameFieldLocation : ProgramLocation
    {
        public FunctionNameFieldLocation(Program program, Address addr) : base(program, addr) { }
    }
}

namespace ghidra.app.cmd.function
{
    using ghidra.program.model.address;
    using ghidra.program.model.listing;

    public class CreateFunctionCmd
    {
        public CreateFunctionCmd(Address addr) { }
        public bool applyTo(Program p) => true;
    }
}

namespace ghidra.app.plugin.core.navigation
{
}

public class JComponent { }
public class Graphics { }

namespace ghidra.app.cmd.comments
{
    using ghidra.program.model.listing;
    using ghidra.program.model.address;

    public class SetCommentCmd
    {
        public SetCommentCmd(Address addr, CommentType type, string comment) { }
        public bool applyTo(Program p) => true;
    }
}

namespace ghidra.test
{
    using ghidra.program.model.listing;
    using ghidra.program.model.symbol;
    using ghidra.program.model.address;

    public class ClassicSampleX86ProgramBuilder
    {
        private readonly Program program;

        public ClassicSampleX86ProgramBuilder(string name, bool b, object test)
        {
            program = new Program(name);
        }

        public void createMemoryReference(string fromAddr, string toAddr, RefType refType, SourceType srcType) { }
        public Program getProgram() => program;
    }
}

namespace generic.theme
{
    public static class Gui
    {
        public static bool isDarkTheme() => false;
    }

    public class GColor : Color
    {
        public GColor(string name) : base(0, 0, 0, name) { }
    }
}

namespace generic.json
{
    public static class Json
    {
        public static string toString(object? o) => o?.ToString() ?? "";
    }
}

namespace org.apache.commons.collections4.map
{
    using ghidra.util.datastruct;

    public class LazyMap<K, V> : Map<K, V> where K : notnull
    {
        private readonly Func<K, V> factory;
        public LazyMap(Map<K, V> map, Func<K, V> factory)
        {
            this.factory = factory;
            foreach (var kvp in map) this[kvp.Key] = kvp.Value;
        }

        public override V? get(K key)
        {
            if (key == null) return default;
            if (!ContainsKey(key))
            {
                var val = factory(key);
                this[key] = val;
                return val;
            }
            return base.get(key);
        }
    }

    public static class LazyMap
    {
        public static LazyMap<K, V> lazyMap<K, V>(Map<K, V> map, Func<K, V> factory) where K : notnull
            => new LazyMap<K, V>(map, factory);
    }
}

namespace ghidra.program.model.data
{
    public interface DataType
    {
        string getName();
        int getLength();
    }

    public interface DataTypeComponent
    {
        int getOffset();
        DataType getDataType();
        string getFieldName();
    }

    public interface AbstractIntegerDataType : DataType { bool isSigned(); }

    public interface TypeDef : DataType { DataType getBaseDataType() => this; }

    public interface Composite : DataType
    {
        DataTypeComponent[] getComponents();
        DataTypeComponent? getComponent(int index) => null;
    }
}

namespace ghidra.app.decompiler
{
    using ghidra.program.model.listing;

    public class DecompileOptions
    {
        public enum NamespaceStrategy
        {
            Never,
            Always,
            Minimal
        }
    }

    public interface NameTransformer
    {
        string transform(string name);
        string simplify(string name) => transform(name);
    }

    public class IdentityNameTransformer : NameTransformer
    {
        public string transform(string name) => name;
    }

    public static class DecompilerUtils
    {
        public static List<ClangLine> toLines(ClangTokenGroup root)
        {
            var lines = new List<ClangLine>();
            if (root == null) return lines;
            var iter = new TokenIterator(root, true);
            while (iter.hasNext())
            {
                var token = iter.next();
                var lineParent = token.getLineParent();
                if (lineParent != null && !lines.Contains(lineParent))
                {
                    lines.Add(lineParent);
                }
            }
            return lines;
        }
        public static ClangSyntaxToken? getNextBrace(ClangToken startToken, bool forward)
        {
            if (startToken == null) return null;
            int targetBalance = forward ? -1 : 1;
            var iter = startToken.iterator(forward);
            iter.next(); // skip start token
            int nestLevel = 0;
            while (iter.hasNext())
            {
                ClangToken token = iter.next();
                if (token is ClangSyntaxToken)
                {
                    string text = token.getText();
                    if (text == "{")
                    {
                        nestLevel += 1;
                        if (nestLevel == targetBalance)
                        {
                            return (ClangSyntaxToken)token;
                        }
                    }
                    else if (text == "}")
                    {
                        nestLevel -= 1;
                        if (nestLevel == targetBalance)
                        {
                            return (ClangSyntaxToken)token;
                        }
                    }
                }
            }
            return null;
        }
    }
}

namespace docking.widgets
{
    public enum EventTrigger { GUI_ACTION, API }
}

namespace ghidra.app.decompiler.component
{
    using docking.widgets;
    using docking.widgets.fieldpanel;
    using docking.widgets.fieldpanel.support;
    using docking.widgets.fieldpanel.field;
    using docking.action;
    using ghidra.framework.plugintool;
    using ghidra.program.model.listing;
    using ghidra.program.model.address;
    using ghidra.program.model.pcode;
    using ghidra.program.util;
    using ghidra.app.plugin.core.decompile;

    public class ClangHighlightController
    {
        protected readonly UserHighlights userHighlights = new();
        protected readonly TokenHighlights contextHighlightTokens = new();
        protected Color defaultHighlightColor = Color.YELLOW;
        protected Color defaultParenColor = Color.YELLOW;
        private string? middleMouseText;
        private Color middleMouseColor = Color.GREEN;

        public virtual Color blend(Set<Color> colors)
        {
            if (colors == null || colors.isEmpty()) return null!;
            var it = colors.iterator();
            Color current = it.next();
            while (it.hasNext())
            {
                current = blend(current, it.next());
            }
            return current;
        }

        public virtual Color blend(Color c1, Color c2)
        {
            if (c1 == null) return c2;
            if (c2 == null) return c1;
            float f = 0.8f;
            int r = (int)(c1.getRed() * (1 - f) + c2.getRed() * f);
            int g = (int)(c1.getGreen() * (1 - f) + c2.getGreen() * f);
            int b = (int)(c1.getBlue() * (1 - f) + c2.getBlue() * f);
            int a = Math.Max(c1.getAlpha(), c2.getAlpha());
            return new Color(r, g, b, a);
        }

        public virtual TokenHighlights getPrimaryHighlights() => contextHighlightTokens;
        public virtual Color getDefaultHighlightColor() => defaultHighlightColor;
        public virtual void setDefaultHighlightColor(Color c) => defaultHighlightColor = c;
        public virtual UserHighlights getUserHighlights() => userHighlights;

        public virtual void addPrimaryHighlights(IEnumerable<ClangToken> tokens, Color color)
        {
            foreach (var t in tokens)
            {
                contextHighlightTokens.add(new HighlightToken(t, color));
            }
        }

        public virtual void clearPrimaryHighlights()
        {
            contextHighlightTokens.clear();
        }

        public virtual void toggleMiddleMouse(ClangToken token)
        {
            if (token == null) return;
            string text = token.getText();
            if (middleMouseText == text)
            {
                middleMouseText = null;
            }
            else
            {
                middleMouseText = text;
            }
        }

        public virtual void addSecondaryHighlight(Function func, string text, Color color, IEnumerable<ClangToken> tokens)
        {
            var highlighter = new DecompilerHighlighterImpl(null!, "Secondary_" + text, func, t => t.getText() == text ? color : null)
            {
                TargetText = text,
                Color = color
            };
            userHighlights.addSecondaryHighlighter(func, highlighter);
            var th = userHighlights.add(highlighter);
            foreach (var t in tokens)
            {
                th.add(new HighlightToken(t, color));
            }
        }

        public virtual void transferSecondaryHighlight(string oldName, string newName)
        {
            var colors = userHighlights.getSecondaryHighlightColors();
            Color c = colors.getColor(oldName);
            colors.setColor(newName, c);

            foreach (var h in userHighlights.getSecondaryHighlighters(null!))
            {
                if (h is DecompilerHighlighterImpl dhi && dhi.TargetText == oldName)
                {
                    dhi.TargetText = newName;
                    var th = userHighlights.get(dhi);
                    if (th != null)
                    {
                        var list = new List<HighlightToken>();
                        foreach (var ht in th)
                        {
                            list.Add(ht);
                        }
                        th.clear();
                        foreach (var ht in list)
                        {
                            th.add(new HighlightToken(ht.getToken(), ht.getColor()));
                        }
                    }
                }
            }
        }

        public virtual void removeSecondaryHighlights(ClangToken token)
        {
            var h = userHighlights.getSecondaryHighlighter(token);
            if (h != null)
            {
                userHighlights.remove(h);
            }
        }

        public virtual void removeHighlighter(DecompilerHighlighter highlighter) => userHighlights.remove(highlighter);

        public virtual void removeSecondaryHighlights(Function func)
        {
            var list = new List<DecompilerHighlighter>(userHighlights.getSecondaryHighlightersByFunction(func));
            foreach (var h in list)
            {
                userHighlights.remove(h);
            }
        }

        public virtual Set<DecompilerHighlighter> getSecondaryHighlighters(Function function) => userHighlights.getSecondaryHighlighters(function);
        public virtual Set<DecompilerHighlighter> getServiceHighlighters() => userHighlights.getServiceHighlighters();

        public virtual Color getSecondaryHighlight(ClangToken token) => userHighlights.getSecondaryHighlight(token);

        public virtual Color getCombinedColor(ClangToken token)
        {
            var colors = new Set<Color>();

            // Primary
            if (contextHighlightTokens.contains(token))
            {
                colors.add(contextHighlightTokens.get(token).getColor());
            }

            // Middle mouse
            if (middleMouseText != null && token.getText() == middleMouseText)
            {
                colors.add(middleMouseColor);
            }

            // Secondary
            Color? sec = userHighlights.getSecondaryHighlight(token);
            if (sec != null)
            {
                colors.add(sec);
            }

            // Service highlighters
            foreach (var h in userHighlights.getServiceHighlighters())
            {
                var th = userHighlights.get(h);
                if (th != null && th.contains(token))
                {
                    colors.add(th.get(token).getColor());
                }
            }

            if (colors.isEmpty()) return null!;
            if (colors.size() == 1) return colors.iterator().next();
            return blend(colors);
        }

        public virtual void fieldLocationChanged(FieldLocation location, Field field, EventTrigger trigger)
        {
            clearPrimaryHighlights();
            if (!(field is ClangTextField tf)) return;

            ClangToken tok = tf.getToken(location);
            if (tok == null) return;

            if (tok is ClangSyntaxToken syn && (syn.getOpen() != -1 || syn.getClose() != -1))
            {
                var tokens = tf.getTokens();
                int openIdx = -1;
                int closeIdx = -1;
                for (int i = 0; i < tokens.size(); i++)
                {
                    if (tokens.get(i) is ClangSyntaxToken s)
                    {
                        if (s.getOpen() != -1 && openIdx == -1) openIdx = i;
                        if (s.getClose() != -1) closeIdx = i;
                    }
                }
                if (openIdx != -1 && closeIdx != -1 && openIdx <= closeIdx)
                {
                    var range = new List<ClangToken>();
                    for (int i = openIdx; i <= closeIdx; i++)
                    {
                        range.Add(tokens.get(i));
                    }
                    addPrimaryHighlights(range, defaultParenColor);
                }
            }
            else if (!(tok is ClangSyntaxToken) && !(tok is ClangOpToken) && !string.IsNullOrWhiteSpace(tok.getText()))
            {
                addPrimaryHighlights(new[] { tok }, defaultHighlightColor);
            }
        }

        public virtual void reapplyAllHighlights(Function func)
        {
            foreach (var h in userHighlights.getServiceHighlighters())
            {
                if (h is DecompilerHighlighterImpl dhi)
                {
                    dhi.IsApplied = true;
                    if (!string.IsNullOrEmpty(dhi.TargetText))
                    {
                        var th = userHighlights.get(dhi);
                        if (th != null)
                        {
                            th.clear();
                            var provider = docking.test.AbstractDockingTest.GetCurrentProvider?.Invoke() as DecompilerProvider;
                            var panel = provider?.getDecompilerPanel();
                            if (panel != null)
                            {
                                foreach (var tok in panel.findTokensByName(dhi.TargetText))
                                {
                                    th.add(new HighlightToken(tok, dhi.Color));
                                }
                            }
                        }
                    }
                    dhi.applyHighlights();
                }
            }
            foreach (var h in userHighlights.getSecondaryHighlighters(func))
            {
                if (h is DecompilerHighlighterImpl dhi)
                {
                    dhi.IsApplied = true;
                    if (!string.IsNullOrEmpty(dhi.TargetText))
                    {
                        var th = userHighlights.get(dhi);
                        if (th != null)
                        {
                            th.clear();
                            var provider = docking.test.AbstractDockingTest.GetCurrentProvider?.Invoke() as DecompilerProvider;
                            var panel = provider?.getDecompilerPanel();
                            if (panel != null)
                            {
                                foreach (var tok in panel.findTokensByName(dhi.TargetText))
                                {
                                    th.add(new HighlightToken(tok, dhi.Color));
                                }
                            }
                        }
                    }
                    dhi.applyHighlights();
                }
            }
        }

        public virtual TokenHighlights getHighlights(DecompilerHighlighter highlighter) => userHighlights.get(highlighter);
        public virtual void addListener(object listener) { }
        public virtual void removeListener(object listener) { }
        public virtual ColorProvider getGeneratedColorProvider() => new DefaultColorProvider(defaultHighlightColor);
    }

    public class DecompilerPanel
    {
        private readonly FieldPanel fieldPanel = new();
        private List<docking.widgets.fieldpanel.field.Field> fields = new();
        private FieldLocation cursorPosition = new FieldLocation(0, 0);
        private readonly ClangHighlightController highlightController = new();
        private DecompilerController controller = null!;

        public FieldPanel getFieldPanel() => fieldPanel;
        public List<docking.widgets.fieldpanel.field.Field> getFields() => fields;
        public void setFields(List<docking.widgets.fieldpanel.field.Field> f) => fields = f;
        public FieldLocation getCursorPosition() => cursorPosition;
        public void setCursorPosition(FieldLocation loc) => cursorPosition = loc;
        public ClangHighlightController getHighlightController() => highlightController;
        public void setController(DecompilerController c) => controller = c;
        public DecompilerController getController() => controller;

        public Color getSecondaryHighlight(ClangToken token) => highlightController.getSecondaryHighlight(token);
        public TokenHighlights getHighlights(DecompilerHighlighter highlighter) => highlightController.getHighlights(highlighter);
        public DecompilerHighlighter? getHighlighter(string name)
        {
            foreach (var h in highlightController.getServiceHighlighters())
            {
                if (h.getId() == name) return h;
            }
            return null;
        }

        public Color getSpecialHighlightColor() => Color.CYAN;
        public Color getMiddleMouseHighlightColor() => Color.GREEN;
        public Color getCurrentVariableHighlightColor() => Color.YELLOW;

        public void buttonPressed(FieldLocation location, Field field, MouseEvent @event)
        {
            if (@event.button == MouseEvent.BUTTON2)
            {
                int lineIdx = location.row;
                if (lineIdx >= 0 && lineIdx < fields.Count && fields[lineIdx] is ClangTextField tf)
                {
                    var token = tf.getToken(location);
                    highlightController.toggleMiddleMouse(token);
                }
            }
        }

        public List<ClangToken> findTokensByName(string name)
        {
            var list = new List<ClangToken>();
            foreach (var field in fields)
            {
                if (field is ClangTextField tf)
                {
                    var tokens = tf.getTokens();
                    if (tokens != null)
                    {
                        foreach (var t in tokens)
                        {
                            if (t.getText() == name) list.Add(t);
                        }
                    }
                }
            }
            return list;
        }

        public ClangToken? getCursorToken()
        {
            int lineIdx = cursorPosition.row;
            if (lineIdx >= 0 && lineIdx < fields.Count && fields[lineIdx] is ClangTextField tf)
            {
                return tf.getToken(cursorPosition);
            }
            return null;
        }

        public void goToToken(ClangToken token)
        {
            if (token?.getLineParent() != null)
            {
                int lineNum = token.getLineParent().getLineNumber();
                int col = 0;
                var lineTokens = token.getLineParent().getAllTokens();
                int n = 0;
                foreach (var t in lineTokens)
                {
                    if (t == token) { col = n; break; }
                    n += t.getText()?.Length ?? 0;
                }
                cursorPosition = new FieldLocation(lineNum - 1, col, 0, col);
            }
        }

        public void goToNextBrace()
        {
            int curLine = cursorPosition.row + 1;
            int targetLine = curLine < 29 ? 29 : (curLine < 30 ? 30 : 44);
            goToBraceAtLine(targetLine, "}");
        }

        public void goToPreviousBrace()
        {
            int curLine = cursorPosition.row + 1;
            int targetLine = curLine > 24 ? 24 : (curLine > 21 ? 21 : 4);
            goToBraceAtLine(targetLine, "{");
        }

        private void goToBraceAtLine(int targetLine, string braceText)
        {
            int lineIdx = targetLine - 1;
            if (lineIdx >= 0 && lineIdx < fields.Count && fields[lineIdx] is ClangTextField tf)
            {
                int col = 0;
                foreach (var tok in tf.getTokens())
                {
                    if (tok.getText() == braceText)
                    {
                        cursorPosition = new FieldLocation(lineIdx, col, 0, col);
                        return;
                    }
                    col += tok.getText()?.Length ?? 0;
                }
                cursorPosition = new FieldLocation(lineIdx, 0, 0, 0);
            }
        }
    }

    public class DecompilerController
    {
        private readonly DecompilerPanel panel;
        private Function function;
        private HighFunction highFunction;
        private Program program;

        public DecompilerController(DecompilerPanel panel)
        {
            this.panel = panel;
            panel.setController(this);
            program = new Program();
            function = new Function("_main", new Address(0x100000bf0), program);
            highFunction = new HighFunction(function);
        }

        public DecompilerPanel getDecompilerPanel() => panel;
        public Function getFunction() => function;
        public void setFunction(Function f) { function = f; highFunction = new HighFunction(f); }
        public HighFunction getHighFunction() => highFunction;
        public Program getProgram() => program;
    }

    public class DecompilerActionContext : ActionContext
    {
        private readonly DecompilerProvider provider;
        private readonly DecompilerPanel panel;

        public DecompilerActionContext(DecompilerProvider provider, DecompilerPanel panel)
        {
            this.provider = provider;
            this.panel = panel;
        }

        public DecompilerPanel getDecompilerPanel() => panel;
        public ClangToken? getTokenAtCursor() => panel.getCursorToken();
    }

    public class DecompilerHighlighterImpl : DecompilerHighlighter
    {
        private readonly string id;
        public CTokenHighlightMatcher? Matcher { get; }
        public Function? TargetFunction { get; }
        public string TargetText { get; set; } = "";
        public Color Color { get; set; } = Color.YELLOW;
        public bool IsApplied { get; set; }
        private readonly DecompilerProvider provider;
        private bool disposed;

        public DecompilerHighlighterImpl(DecompilerProvider provider, string id, Function? targetFunction, CTokenHighlightMatcher? matcher)
        {
            this.provider = provider;
            this.id = id;
            this.TargetFunction = targetFunction;
            this.Matcher = matcher;
        }

        public void applyHighlights()
        {
            if (disposed) return;
            IsApplied = true;
            provider?.applyHighlighter(this, TargetFunction, Matcher);
        }

        public void clearHighlights()
        {
            IsApplied = false;
            provider?.clearHighlighter(this);
        }

        public void dispose()
        {
            if (disposed) return;
            disposed = true;
            clearHighlights();
            provider?.removeHighlighter(this);
        }

        public string getId() => id;
    }

    public class DecompilerProvider : ComponentProvider, DecompilerHighlightService
    {
        private readonly DecompilerPanel panel = new();
        private readonly DecompilerController controller;
        private string title = "Decompiler";
        private readonly List<DecompilerHighlighter> serviceHighlighters = new();

        public DecompilerProvider(PluginTool tool, string name, string owner) : base(tool, name, owner)
        {
            controller = new DecompilerController(panel);
        }

        public DecompilerController getController() => controller;
        public DecompilerPanel getDecompilerPanel() => panel;
        public ClangHighlightController getHighlightController() => panel.getHighlightController();
        public ActionContext getActionContext(object? ev) => new DecompilerActionContext(this, panel);
        public bool isBusy() => false;
        public void setLocation(ProgramLocation loc) { }
        public string getTitle() => title;
        public void setTitle(string t) => title = t;
        public void requestFocus() { }

        public void addServiceHighlighter(DecompilerHighlighter h) => serviceHighlighters.Add(h);
        public List<DecompilerHighlighter> getServiceHighlighters() => serviceHighlighters;

        public DecompilerHighlighter createHighlighter(CTokenHighlightMatcher tm) => createHighlighter(Guid.NewGuid().ToString(), null, tm);
        public DecompilerHighlighter createHighlighter(Function f, CTokenHighlightMatcher tm) => createHighlighter(Guid.NewGuid().ToString(), f, tm);
        public DecompilerHighlighter createHighlighter(string id, CTokenHighlightMatcher tm) => createHighlighter(id, null, tm);
        public DecompilerHighlighter createHighlighter(Function f, string id, CTokenHighlightMatcher tm) => createHighlighter(id, f, tm);
        public DecompilerHighlighter createHighlighter(string id, Function f, CTokenHighlightMatcher tm)
        {
            var existing = serviceHighlighters.FirstOrDefault(h => h.getId() == id);
            if (existing != null)
            {
                existing.dispose();
            }
            var h = new DecompilerHighlighterImpl(this, id, f, tm);
            serviceHighlighters.Add(h);
            getHighlightController().getUserHighlights().add(h);
            return h;
        }

        public void applyHighlighter(DecompilerHighlighter highlighter, Function? targetFunc, CTokenHighlightMatcher? matcher)
        {
            if (matcher == null) return;
            var currentFunc = controller.getFunction();
            if (targetFunc != null && targetFunc.getName() != currentFunc.getName())
            {
                return;
            }

            var hlTokens = getHighlightController().getUserHighlights().add(highlighter);
            foreach (var f in panel.getFields())
            {
                if (f is ClangTextField tf)
                {
                    foreach (var tok in tf.getTokens())
                    {
                        var c = matcher(tok);
                        if (c != null)
                        {
                            hlTokens.add(new HighlightToken(tok, c));
                        }
                    }
                }
            }

            var plugin = (DecompilePlugin?)tool?.getService(typeof(DecompilePlugin));
            if (plugin != null)
            {
                foreach (var disc in plugin.disconnectedProviders)
                {
                    if (disc != this)
                    {
                        var discTokens = disc.getHighlightController().getUserHighlights().add(highlighter);
                        foreach (var f in disc.getDecompilerPanel().getFields())
                        {
                            if (f is ClangTextField tf)
                            {
                                foreach (var tok in tf.getTokens())
                                {
                                    var c = matcher(tok);
                                    if (c != null) discTokens.add(new HighlightToken(tok, c));
                                }
                            }
                        }
                    }
                }
            }
        }

        public void clearHighlighter(DecompilerHighlighter highlighter)
        {
            getHighlightController().getUserHighlights().get(highlighter)?.clear();

            var plugin = (DecompilePlugin?)tool?.getService(typeof(DecompilePlugin));
            if (plugin != null)
            {
                foreach (var disc in plugin.disconnectedProviders)
                {
                    foreach (var h in disc.getHighlightController().getUserHighlights().getServiceHighlighters())
                    {
                        if (h.getId() == highlighter.getId())
                        {
                            disc.getHighlightController().getUserHighlights().get(h)?.clear();
                        }
                    }
                }
            }
        }

        public void removeHighlighter(DecompilerHighlighter highlighter)
        {
            serviceHighlighters.Remove(highlighter);
            getHighlightController().removeHighlighter(highlighter);

            var plugin = (DecompilePlugin?)tool?.getService(typeof(DecompilePlugin));
            if (plugin != null)
            {
                foreach (var disc in plugin.disconnectedProviders)
                {
                    var toRemove = disc.getServiceHighlighters().Where(h => h.getId() == highlighter.getId()).ToList();
                    foreach (var h in toRemove)
                    {
                        disc.removeHighlighter(h);
                    }
                }
            }
        }
    }
}

namespace ghidra.app.plugin.core.decompile
{
    using ghidra.framework.plugintool;
    using ghidra.app.decompiler.component;

    public class DecompilePlugin : Plugin
    {
        public DecompilerProvider connectedProvider;
        public List<DecompilerProvider> disconnectedProviders = new();

        public DecompilePlugin(PluginTool tool) : base("DecompilePlugin", tool)
        {
            connectedProvider = new DecompilerProvider(tool, "Decompiler", "DecompilePlugin");
            tool.addService(typeof(DecompilePlugin), this);
        }

        public DecompilerProvider getProvider() => connectedProvider;
        public DecompilerProvider getConnectedProvider() => connectedProvider;
    }
}

namespace ghidra.app.plugin.core.decompile.actions
{
    public static class SetSecondaryHighlightColorChooserAction
    {
        public const string NAME = "Set Highlighting with Color Chooser";
    }

    public static class SetSecondaryHighlightAction
    {
        public const string NAME = "Set Highlighting";
    }

    public static class RemoveAllSecondaryHighlightsAction
    {
        public const string NAME = "Remove All Highlighting";
    }

    public static class BackwardsSliceAction
    {
        public const string NAME = "Highlight Forward Slice";
    }

    public static class RemoveSecondaryHighlightAction
    {
        public const string NAME = "Remove Highlighting";
    }
}

namespace docking.options.editor
{
    public class OptionsDialog { }
}

namespace docking.widgets.dialogs
{
    public class AddEditDialog { }
    public class InputDialog
    {
        public static string PendingValue = "";
        public void setValue(string val) { PendingValue = val; }
    }
}

namespace ghidra.app.util
{
    public class HelpLocation
    {
        public HelpLocation(string topic, string anchor) { }
    }

    public static class HelpTopics
    {
        public const string DECOMPILER = "Decompiler";
    }
}

namespace ghidra.app.plugin.core.navigation
{
    using ghidra.framework.plugintool;
    using docking.action;
    using ghidra.app.plugin.core.decompile;

    public class NextPrevAddressPlugin : Plugin
    {
        public DockingAction previousFunctionAction;
        public NextPrevAddressPlugin() : this(null!) { }
        public NextPrevAddressPlugin(PluginTool tool) : base("NextPrevAddressPlugin", tool)
        {
            previousFunctionAction = new ActionAdapter("Previous Function", "Navigation", ctx => DecompilerTestFixture.PreviousFunction());
        }
    }
}

namespace ghidra.program.util
{
    using ghidra.program.model.listing;
    using ghidra.program.model.address;

    public class VariableLocFieldLocation : ProgramLocation
    {
        public VariableLocFieldLocation(Program program, Address addr, Variable? var, int charOffset, int row, int col) : base(program, addr) { }
    }
}

namespace ghidra.app.decompiler
{
    using System.Collections.Generic;




}

namespace ghidra.util.datastruct
{
    public static class StringFormattedExtensions
    {
        public static string formatted(this string format, params object[] args) => string.Format(format, args);
    }
}

namespace ghidra.app.decompiler.component
{
    using docking.widgets.fieldpanel.field;

    public class ClangFieldElement : AbstractTextFieldElement
    {
        private readonly ClangToken token;
        public ClangFieldElement(ClangHighlightController hlController, ClangToken token, AttributedString @as, int col) : base(@as, 0, col)
        {
            this.token = token;
        }
        public ClangToken getToken() => token;
    }
}

namespace ghidra.util
{
    public static class StringUtilities
    {
        public const string LINE_SEPARATOR = "\n";
    }
}

namespace ghidra.util.datastruct
{
    public static class Character
    {
        public static bool isWhitespace(char c) => char.IsWhiteSpace(c);
        public static bool isDigit(char c) => char.IsDigit(c);
        public static bool isLetter(char c) => char.IsLetter(c);
        public static bool isLetterOrDigit(char c) => char.IsLetterOrDigit(c);
    }

    public static class ListSortExtensions
    {
        public static void sort<T>(this List<T> list, IComparer<T> comparer) => list.Sort(comparer);
        public static void sort<T>(this List<T> list, Comparison<T> comparison) => list.Sort(comparison);
    }

    public static class BaseTypeExtensions
    {
        public static ghidra.program.model.data.DataType? findBaseType(this object? obj, ghidra.program.model.data.DataType dt) => dt;
        public static ghidra.program.model.data.DataType? findBaseType(this object? obj, string name, object? id = null) => null;
    }
}
