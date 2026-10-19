namespace ghidra.util.datastruct;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;

#region Java Primitive Wrappers

public readonly struct JavaLong : IComparable<JavaLong>, IEquatable<JavaLong>, IComparable<long>, IEquatable<long>
{
    private readonly long _value;

    public JavaLong(long value) => _value = value;

    public const long MAX_VALUE = long.MaxValue;
    public const long MIN_VALUE = long.MinValue;
    public const int SIZE = 64;
    public const int BYTES = 8;

    public static implicit operator long(JavaLong l) => l._value;
    public static implicit operator JavaLong(long l) => new(l);

    public static string toHexString(long i) => ((ulong)i).ToString("x");
    public static string toOctalString(long i) => Convert.ToString(i, 8);
    public static string toBinaryString(long i) => Convert.ToString(i, 2);
    public static string toString(long i) => i.ToString();
    public static string toString(long i, int radix) => Convert.ToString(i, radix);

    public static long parseLong(string s) => long.Parse(s, CultureInfo.InvariantCulture);
    public static long parseLong(string s, int radix) => Convert.ToInt64(s, radix);

    public static int compare(long x, long y) => x.CompareTo(y);
    public static int compareUnsigned(long x, long y) => ((ulong)x).CompareTo((ulong)y);
    public static long divideUnsigned(long dividend, long divisor) => (long)((ulong)dividend / (ulong)divisor);
    public static long remainderUnsigned(long dividend, long divisor) => (long)((ulong)dividend % (ulong)divisor);

    public static int numberOfLeadingZeros(long i) => BitOperations.LeadingZeroCount((ulong)i);
    public static int numberOfTrailingZeros(long i) => BitOperations.TrailingZeroCount((ulong)i);
    public static int bitCount(long i) => BitOperations.PopCount((ulong)i);
    public static long reverseBytes(long i) => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(i);

    public static long highestOneBit(long i)
    {
        i |= (i >> 1);
        i |= (i >> 2);
        i |= (i >> 4);
        i |= (i >> 8);
        i |= (i >> 16);
        i |= (i >> 32);
        return i - (long)((ulong)i >> 1);
    }

    public static long lowestOneBit(long i) => i & -i;

    public static JavaLong valueOf(long l) => new(l);
    public static JavaLong valueOf(string s) => new(parseLong(s));
    public static JavaLong valueOf(string s, int radix) => new(parseLong(s, radix));

    public static JavaLong decode(string nm)
    {
        if (nm.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || nm.StartsWith("#"))
        {
            return parseLong(nm.Replace("#", "").Substring(nm.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0), 16);
        }
        return parseLong(nm);
    }

    public int CompareTo(JavaLong other) => _value.CompareTo(other._value);
    public int CompareTo(long other) => _value.CompareTo(other);
    public bool Equals(JavaLong other) => _value == other._value;
    public bool Equals(long other) => _value == other;
    public override bool Equals(object? obj) => obj is JavaLong l && Equals(l) || obj is long lo && Equals(lo);
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString();
}

public readonly struct JavaInteger : IComparable<JavaInteger>, IEquatable<JavaInteger>, IComparable<int>, IEquatable<int>
{
    private readonly int _value;

    public JavaInteger(int value) => _value = value;

    public const int MAX_VALUE = int.MaxValue;
    public const int MIN_VALUE = int.MinValue;
    public const int SIZE = 32;
    public const int BYTES = 4;

    public static implicit operator int(JavaInteger i) => i._value;
    public static implicit operator JavaInteger(int i) => new(i);

    public static string toHexString(int i) => ((uint)i).ToString("x");
    public static string toOctalString(int i) => Convert.ToString(i, 8);
    public static string toBinaryString(int i) => Convert.ToString(i, 2);
    public static string toString(int i) => i.ToString();
    public static string toString(int i, int radix) => Convert.ToString(i, radix);

    public static int parseInt(string s) => int.Parse(s, CultureInfo.InvariantCulture);
    public static int parseInt(string s, int radix) => Convert.ToInt32(s, radix);

    public static int compare(int x, int y) => x.CompareTo(y);
    public static int compareUnsigned(int x, int y) => ((uint)x).CompareTo((uint)y);
    public static int divideUnsigned(int dividend, int divisor) => (int)((uint)dividend / (uint)divisor);
    public static int remainderUnsigned(int dividend, int divisor) => (int)((uint)dividend % (uint)divisor);

    public static int numberOfLeadingZeros(int i) => BitOperations.LeadingZeroCount((uint)i);
    public static int numberOfTrailingZeros(int i) => BitOperations.TrailingZeroCount((uint)i);
    public static int bitCount(int i) => BitOperations.PopCount((uint)i);
    public static int reverseBytes(int i) => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(i);

    public static int highestOneBit(int i)
    {
        i |= (i >> 1);
        i |= (i >> 2);
        i |= (i >> 4);
        i |= (i >> 8);
        i |= (i >> 16);
        return i - (int)((uint)i >> 1);
    }

    public static int lowestOneBit(int i) => i & -i;

    public static JavaInteger valueOf(int i) => new(i);
    public static JavaInteger valueOf(string s) => new(parseInt(s));
    public static JavaInteger valueOf(string s, int radix) => new(parseInt(s, radix));

    public static JavaInteger decode(string nm)
    {
        if (nm.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || nm.StartsWith("#"))
        {
            return parseInt(nm.Replace("#", "").Substring(nm.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? 2 : 0), 16);
        }
        return parseInt(nm);
    }

    public int CompareTo(JavaInteger other) => _value.CompareTo(other._value);
    public int CompareTo(int other) => _value.CompareTo(other);
    public bool Equals(JavaInteger other) => _value == other._value;
    public bool Equals(int other) => _value == other;
    public override bool Equals(object? obj) => obj is JavaInteger i && Equals(i) || obj is int io && Equals(io);
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString();
}

public readonly struct JavaShort : IComparable<JavaShort>, IEquatable<JavaShort>
{
    private readonly short _value;
    public JavaShort(short value) => _value = value;

    public const short MAX_VALUE = short.MaxValue;
    public const short MIN_VALUE = short.MinValue;
    public const int SIZE = 16;
    public const int BYTES = 2;

    public static implicit operator short(JavaShort s) => s._value;
    public static implicit operator JavaShort(short s) => new(s);

    public static short parseShort(string s) => short.Parse(s, CultureInfo.InvariantCulture);
    public static short parseShort(string s, int radix) => Convert.ToInt16(s, radix);
    public static int compare(short x, short y) => x.CompareTo(y);
    public static short reverseBytes(short s) => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(s);
    public static JavaShort valueOf(short s) => new(s);
    public static int toUnsignedInt(short s) => (ushort)s;
    public static long toUnsignedLong(short s) => (ushort)s;

    public int CompareTo(JavaShort other) => _value.CompareTo(other._value);
    public bool Equals(JavaShort other) => _value == other._value;
    public override bool Equals(object? obj) => obj is JavaShort s && Equals(s) || obj is short so && _value == so;
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString();
}

public readonly struct JavaByte : IComparable<JavaByte>, IEquatable<JavaByte>
{
    private readonly byte _value;
    public JavaByte(byte value) => _value = value;

    public const byte MAX_VALUE = 0x7F;
    public const byte MIN_VALUE = 0x80;
    public const int SIZE = 8;
    public const int BYTES = 1;

    public static implicit operator byte(JavaByte b) => b._value;
    public static implicit operator JavaByte(byte b) => new(b);

    public static sbyte parseByte(string s) => sbyte.Parse(s, CultureInfo.InvariantCulture);
    public static sbyte parseByte(string s, int radix) => Convert.ToSByte(s, radix);
    public static int compare(byte x, byte y) => x.CompareTo(y);
    public static JavaByte valueOf(byte b) => new(b);
    public static int toUnsignedInt(byte b) => b;
    public static long toUnsignedLong(byte b) => b;

    public int CompareTo(JavaByte other) => _value.CompareTo(other._value);
    public bool Equals(JavaByte other) => _value == other._value;
    public override bool Equals(object? obj) => obj is JavaByte b && Equals(b) || obj is byte bo && _value == bo;
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString();
}

public readonly struct JavaDouble : IComparable<JavaDouble>, IEquatable<JavaDouble>
{
    private readonly double _value;
    public JavaDouble(double value) => _value = value;

    public const double MAX_VALUE = double.MaxValue;
    public const double MIN_VALUE = double.Epsilon;
    public const double NaN = double.NaN;
    public const double POSITIVE_INFINITY = double.PositiveInfinity;
    public const double NEGATIVE_INFINITY = double.NegativeInfinity;

    public static implicit operator double(JavaDouble d) => d._value;
    public static implicit operator JavaDouble(double d) => new(d);

    public static double parseDouble(string s) => double.Parse(s, CultureInfo.InvariantCulture);
    public static bool isNaN(double v) => double.IsNaN(v);
    public static bool isInfinite(double v) => double.IsInfinity(v);
    public static double longBitsToDouble(long bits) => BitConverter.Int64BitsToDouble(bits);
    public static long doubleToLongBits(double value) => BitConverter.DoubleToInt64Bits(value);
    public static long doubleToRawLongBits(double value) => BitConverter.DoubleToInt64Bits(value);
    public static int compare(double d1, double d2) => d1.CompareTo(d2);
    public static JavaDouble valueOf(double d) => new(d);

    public int CompareTo(JavaDouble other) => _value.CompareTo(other._value);
    public bool Equals(JavaDouble other) => _value.Equals(other._value);
    public override bool Equals(object? obj) => obj is JavaDouble d && Equals(d) || obj is double @do && _value.Equals(@do);
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString(CultureInfo.InvariantCulture);
}

public readonly struct JavaFloat : IComparable<JavaFloat>, IEquatable<JavaFloat>
{
    private readonly float _value;
    public JavaFloat(float value) => _value = value;

    public const float MAX_VALUE = float.MaxValue;
    public const float MIN_VALUE = float.Epsilon;
    public const float NaN = float.NaN;
    public const float POSITIVE_INFINITY = float.PositiveInfinity;
    public const float NEGATIVE_INFINITY = float.NegativeInfinity;

    public static implicit operator float(JavaFloat f) => f._value;
    public static implicit operator JavaFloat(float f) => new(f);

    public static float parseFloat(string s) => float.Parse(s, CultureInfo.InvariantCulture);
    public static bool isNaN(float v) => float.IsNaN(v);
    public static bool isInfinite(float v) => float.IsInfinity(v);
    public static float intBitsToFloat(int bits) => BitConverter.Int32BitsToSingle(bits);
    public static int floatToIntBits(float value) => BitConverter.SingleToInt32Bits(value);
    public static int floatToRawIntBits(float value) => BitConverter.SingleToInt32Bits(value);
    public static int compare(float f1, float f2) => f1.CompareTo(f2);
    public static JavaFloat valueOf(float f) => new(f);

    public int CompareTo(JavaFloat other) => _value.CompareTo(other._value);
    public bool Equals(JavaFloat other) => _value.Equals(other._value);
    public override bool Equals(object? obj) => obj is JavaFloat f && Equals(f) || obj is float fo && _value.Equals(fo);
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value.ToString(CultureInfo.InvariantCulture);
}

public readonly struct JavaBoolean : IComparable<JavaBoolean>, IEquatable<JavaBoolean>
{
    private readonly bool _value;
    public JavaBoolean(bool value) => _value = value;

    public static readonly JavaBoolean TRUE = new(true);
    public static readonly JavaBoolean FALSE = new(false);

    public static implicit operator bool(JavaBoolean b) => b._value;
    public static implicit operator JavaBoolean(bool b) => new(b);

    public static bool parseBoolean(string? s) => bool.TryParse(s, out var b) && b;
    public static JavaBoolean valueOf(bool b) => b ? TRUE : FALSE;
    public static JavaBoolean valueOf(string? s) => parseBoolean(s) ? TRUE : FALSE;
    public static int compare(bool x, bool y) => x.CompareTo(y);
    public static bool logicalAnd(bool a, bool b) => a && b;
    public static bool logicalOr(bool a, bool b) => a || b;
    public static bool logicalXor(bool a, bool b) => a ^ b;

    public int CompareTo(JavaBoolean other) => _value.CompareTo(other._value);
    public bool Equals(JavaBoolean other) => _value == other._value;
    public override bool Equals(object? obj) => obj is JavaBoolean b && Equals(b) || obj is bool bo && _value == bo;
    public override int GetHashCode() => _value.GetHashCode();
    public override string ToString() => _value ? "true" : "false";
}

public static class JavaCharacter
{
    public const char MIN_VALUE = '\u0000';
    public const char MAX_VALUE = '\uffff';

    public static bool isWhitespace(char c) => char.IsWhiteSpace(c);
    public static bool isDigit(char c) => char.IsDigit(c);
    public static bool isLetter(char c) => char.IsLetter(c);
    public static bool isLetterOrDigit(char c) => char.IsLetterOrDigit(c);
    public static bool isUpperCase(char c) => char.IsUpper(c);
    public static bool isLowerCase(char c) => char.IsLower(c);
    public static char toUpperCase(char c) => char.ToUpperInvariant(c);
    public static char toLowerCase(char c) => char.ToLowerInvariant(c);
    public static bool isISOControl(char c) => char.IsControl(c);
    public static bool isJavaIdentifierStart(char c) => char.IsLetter(c) || c == '_' || c == '$';
    public static bool isJavaIdentifierPart(char c) => char.IsLetterOrDigit(c) || c == '_' || c == '$';
    public static int compare(char x, char y) => x.CompareTo(y);
    public static char valueOf(char c) => c;

    public static int digit(char ch, int radix)
    {
        if (radix < 2 || radix > 36) return -1;
        if (ch >= '0' && ch <= '9')
        {
            int val = ch - '0';
            return val < radix ? val : -1;
        }
        if (ch >= 'a' && ch <= 'z')
        {
            int val = ch - 'a' + 10;
            return val < radix ? val : -1;
        }
        if (ch >= 'A' && ch <= 'Z')
        {
            int val = ch - 'A' + 10;
            return val < radix ? val : -1;
        }
        return -1;
    }

    public static char forDigit(int digit, int radix)
    {
        if (digit < 0 || digit >= radix || radix < 2 || radix > 36) return '\0';
        return digit < 10 ? (char)('0' + digit) : (char)('a' + digit - 10);
    }
}

public static class JavaMath
{
    public const double PI = Math.PI;
    public const double E = Math.E;

    public static double log(double a) => Math.Log(a);
    public static double log10(double a) => Math.Log10(a);
    public static double max(double a, double b) => Math.Max(a, b);
    public static float max(float a, float b) => Math.Max(a, b);
    public static long max(long a, long b) => Math.Max(a, b);
    public static int max(int a, int b) => Math.Max(a, b);
    public static double min(double a, double b) => Math.Min(a, b);
    public static float min(float a, float b) => Math.Min(a, b);
    public static long min(long a, long b) => Math.Min(a, b);
    public static int min(int a, int b) => Math.Min(a, b);
    public static double abs(double a) => Math.Abs(a);
    public static float abs(float a) => Math.Abs(a);
    public static long abs(long a) => Math.Abs(a);
    public static int abs(int a) => Math.Abs(a);
    public static double pow(double a, double b) => Math.Pow(a, b);
    public static double sqrt(double a) => Math.Sqrt(a);
    public static double ceil(double a) => Math.Ceiling(a);
    public static double floor(double a) => Math.Floor(a);
    public static long round(double a) => (long)Math.Round(a);
    public static int round(float a) => (int)Math.Round(a);
    public static double sin(double a) => Math.Sin(a);
    public static double cos(double a) => Math.Cos(a);
    public static double tan(double a) => Math.Tan(a);
    public static double asin(double a) => Math.Asin(a);
    public static double acos(double a) => Math.Acos(a);
    public static double atan(double a) => Math.Atan(a);
    public static double atan2(double y, double x) => Math.Atan2(y, x);
    public static double exp(double a) => Math.Exp(a);
    public static double hypot(double x, double y) => Math.Sqrt(x * x + y * y);

    // PascalCase compatibility
    public static double Log(double a) => Math.Log(a);
    public static double Max(double a, double b) => Math.Max(a, b);
    public static long Max(long a, long b) => Math.Max(a, b);
    public static int Max(int a, int b) => Math.Max(a, b);
    public static double Min(double a, double b) => Math.Min(a, b);
    public static long Min(long a, long b) => Math.Min(a, b);
    public static int Min(int a, int b) => Math.Min(a, b);
    public static double Abs(double a) => Math.Abs(a);
    public static long Abs(long a) => Math.Abs(a);
    public static int Abs(int a) => Math.Abs(a);
    public static double Pow(double a, double b) => Math.Pow(a, b);
    public static double Sqrt(double a) => Math.Sqrt(a);
    public static double Ceiling(double a) => Math.Ceiling(a);
    public static double Floor(double a) => Math.Floor(a);
    public static long Round(double a) => (long)Math.Round(a);
}

public static class Objects
{
    public static T requireNonNull<T>(T? obj) => obj ?? throw new NullPointerException();
    public static T requireNonNull<T>(T? obj, string message) => obj ?? throw new NullPointerException(message);
    public static bool equals(object? a, object? b) => Equals(a, b);
    public static int hashCode(object? o) => o?.GetHashCode() ?? 0;
    public static int hash(params object?[] values)
    {
        if (values == null) return 0;
        int result = 1;
        foreach (var element in values)
        {
            result = 31 * result + (element == null ? 0 : element.GetHashCode());
        }
        return result;
    }
    public static string toString(object? o) => o?.ToString() ?? "null";
    public static string toString(object? o, string nullDefault) => o?.ToString() ?? nullDefault;
    public static bool nonNull(object? obj) => obj != null;
    public static bool isNull(object? obj) => obj == null;
}

#endregion

#region Java Standard Exceptions

public class AssertException : Exception
{
    public AssertException() : base() { }
    public AssertException(string? message) : base(message) { }
    public AssertException(Exception? cause) : base(cause?.Message, cause) { }
    public AssertException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class DuplicateNameException : Exception
{
    public DuplicateNameException() : base() { }
    public DuplicateNameException(string? message) : base(message) { }
    public DuplicateNameException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class NumberFormatException : FormatException
{
    public NumberFormatException() : base() { }
    public NumberFormatException(string? message) : base(message) { }
    public NumberFormatException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class ConcurrentModificationException : InvalidOperationException
{
    public ConcurrentModificationException() : base() { }
    public ConcurrentModificationException(string? message) : base(message) { }
    public ConcurrentModificationException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class AssertionError : Exception
{
    public AssertionError() : base() { }
    public AssertionError(string? message) : base(message) { }
    public AssertionError(object? detailMessage) : base(detailMessage?.ToString()) { }
    public AssertionError(string? message, Exception? innerException) : base(message, innerException) { }
}

public class StringBuffer
{
    private readonly StringBuilder _sb;
    public StringBuffer() => _sb = new();
    public StringBuffer(int capacity) => _sb = new(capacity);
    public StringBuffer(string str) => _sb = new(str);
    public StringBuffer append(string? s) { _sb.Append(s); return this; }
    public StringBuffer append(object? o) { _sb.Append(o); return this; }
    public StringBuffer append(char c) { _sb.Append(c); return this; }
    public StringBuffer append(int i) { _sb.Append(i); return this; }
    public StringBuffer append(long l) { _sb.Append(l); return this; }
    public int length() => _sb.Length;
    public char charAt(int index) => _sb[index];
    public StringBuffer deleteCharAt(int index) { _sb.Remove(index, 1); return this; }
    public override string ToString() => _sb.ToString();
    public static implicit operator string(StringBuffer sb) => sb.ToString();
}

#endregion

#region Java Extension Methods

public static class JavaExtensions
{
    // Object extensions
    public static bool equals(this object? a, object? b) => Equals(a, b);
    public static int hashCode(this object? a) => a?.GetHashCode() ?? 0;
    public static string toString(this object? a) => a?.ToString() ?? "null";
    public static Type getClass(this object a) => a.GetType();

    // Type extensions
    public static string getName(this Type t) => t.Name;
    public static string getSimpleName(this Type t) => t.Name;
    public static string getCanonicalName(this Type t) => t.FullName ?? t.Name;

    // Exception extensions
    public static string getMessage(this Exception ex) => ex.Message;
    public static Exception? getCause(this Exception ex) => ex.InnerException;
    public static void printStackTrace(this Exception ex) => Console.Error.WriteLine(ex);

    // String extensions
    public static char charAt(this string s, int index) => s[index];
    public static int length(this string s) => s.Length;
    public static bool startsWith(this string s, string prefix) => s.StartsWith(prefix, StringComparison.Ordinal);
    public static bool startsWith(this string s, string prefix, int toffset) => toffset >= 0 && toffset <= s.Length && s.Substring(toffset).StartsWith(prefix, StringComparison.Ordinal);
    public static bool endsWith(this string s, string suffix) => s.EndsWith(suffix, StringComparison.Ordinal);
    public static int indexOf(this string s, string str) => s.IndexOf(str, StringComparison.Ordinal);
    public static int indexOf(this string s, string str, int fromIndex) => s.IndexOf(str, fromIndex, StringComparison.Ordinal);
    public static int indexOf(this string s, char ch) => s.IndexOf(ch);
    public static int indexOf(this string s, char ch, int fromIndex) => s.IndexOf(ch, fromIndex);
    public static int lastIndexOf(this string s, string str) => s.LastIndexOf(str, StringComparison.Ordinal);
    public static int lastIndexOf(this string s, char ch) => s.LastIndexOf(ch);
    public static string substring(this string s, int beginIndex) => s.Substring(beginIndex);
    public static string substring(this string s, int beginIndex, int endIndex) => s.Substring(beginIndex, endIndex - beginIndex);
    public static string toLowerCase(this string s) => s.ToLowerInvariant();
    public static string toUpperCase(this string s) => s.ToUpperInvariant();
    public static string trim(this string s) => s.Trim();
    public static string replaceAll(this string s, string regex, string replacement) => Regex.Replace(s, regex, replacement);
    public static string replace(this string s, char oldChar, char newChar) => s.Replace(oldChar, newChar);
    public static string replace(this string s, string oldValue, string newValue) => s.Replace(oldValue, newValue);
    public static string[] split(this string s, string regex) => Regex.Split(s, regex);
    public static bool equalsIgnoreCase(this string s, string? another) => string.Equals(s, another, StringComparison.OrdinalIgnoreCase);
    public static int compareTo(this string s, string another) => string.CompareOrdinal(s, another);
    public static int compareToIgnoreCase(this string s, string str) => string.Compare(s, str, StringComparison.OrdinalIgnoreCase);
    public static byte[] getBytes(this string s) => Encoding.UTF8.GetBytes(s);
    public static bool isEmpty(this string s) => string.IsNullOrEmpty(s);
    public static bool regionMatches(this string s, bool ignoreCase, int toffset, string other, int ooffset, int len)
    {
        if (toffset < 0 || ooffset < 0 || toffset + len > s.Length || ooffset + len > other.Length) return false;
        return string.Compare(s, toffset, other, ooffset, len, ignoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) == 0;
    }
    public static bool regionMatches(this string s, int toffset, string other, int ooffset, int len) => regionMatches(s, false, toffset, other, ooffset, len);

    public static StringBuilder append(this StringBuilder sb, string? s) => sb.Append(s);
    public static StringBuilder append(this StringBuilder sb, object? o) => sb.Append(o);
    public static StringBuilder append(this StringBuilder sb, char c) => sb.Append(c);
    public static StringBuilder append(this StringBuilder sb, int i) => sb.Append(i);
    public static StringBuilder append(this StringBuilder sb, long l) => sb.Append(l);
    public static StringBuilder append(this StringBuilder sb, bool b) => sb.Append(b);
    public static StringBuilder append(this StringBuilder sb, float f) => sb.Append(f);
    public static StringBuilder append(this StringBuilder sb, double d) => sb.Append(d);
    public static StringBuilder append(this StringBuilder sb, char[] str, int offset, int len) => sb.Append(str, offset, len);
    public static StringBuilder appendCodePoint(this StringBuilder sb, int codePoint) => sb.Append(char.ConvertFromUtf32(codePoint));
    public static string toString(this StringBuilder sb) => sb.ToString();
    public static int length(this StringBuilder sb) => sb.Length;
    public static void setLength(this StringBuilder sb, int newLength) => sb.Length = newLength;
    public static char charAt(this StringBuilder sb, int index) => sb[index];
    public static StringBuilder delete(this StringBuilder sb, int start, int end) => sb.Remove(start, end - start);
    public static StringBuilder deleteCharAt(this StringBuilder sb, int index) => sb.Remove(index, 1);

    // Array extensions
    public static int length<T>(this T[] arr) => arr.Length;
    public static int length(this Array arr) => arr.Length;

    // Collection extensions
    public static int size<T>(this ICollection<T> collection) => collection.Count;
    public static bool isEmpty<T>(this ICollection<T> collection) => collection.Count == 0;
    public static bool contains<T>(this ICollection<T> collection, T item) => collection.Contains(item);
    public static bool add<T>(this ICollection<T> collection, T item) { collection.Add(item); return true; }
    public static bool remove<T>(this ICollection<T> collection, T item) => collection.Remove(item);
    public static void clear<T>(this ICollection<T> collection) => collection.Clear();
    public static T[] toArray<T>(this ICollection<T> collection) => collection.ToArray();
    public static T[] toArray<T>(this ICollection<T> collection, T[] a)
    {
        if (a.Length < collection.Count)
        {
            return collection.ToArray();
        }
        collection.CopyTo(a, 0);
        return a;
    }

    // List extensions
    public static T get<T>(this IList<T> list, int index) => list[index];
    public static T set<T>(this IList<T> list, int index, T element) { T old = list[index]; list[index] = element; return old; }
    public static void add<T>(this IList<T> list, int index, T item) => list.Insert(index, item);
    public static T remove<T>(this IList<T> list, int index) { T item = list[index]; list.RemoveAt(index); return item; }

    // Dictionary extensions
    public static V? get<K, V>(this IDictionary<K, V> dict, K key) => dict.TryGetValue(key, out var val) ? val : default;
    public static V? put<K, V>(this IDictionary<K, V> dict, K key, V val) { dict.TryGetValue(key, out var old); dict[key] = val; return old; }
    public static bool containsKey<K, V>(this IDictionary<K, V> dict, K key) => dict.ContainsKey(key);
    public static bool containsValue<K, V>(this IDictionary<K, V> dict, V value) => dict.Values.Contains(value);
    public static V? remove<K, V>(this IDictionary<K, V> dict, K key) { if (dict.TryGetValue(key, out var val)) { dict.Remove(key); return val; } return default; }
    public static ICollection<K> keySet<K, V>(this IDictionary<K, V> dict) => dict.Keys;
    public static ICollection<V> values<K, V>(this IDictionary<K, V> dict) => dict.Values;

    // BigInteger extensions
    public static BigInteger add(this BigInteger a, BigInteger b) => a + b;
    public static BigInteger subtract(this BigInteger a, BigInteger b) => a - b;
    public static BigInteger multiply(this BigInteger a, BigInteger b) => a * b;
    public static BigInteger divide(this BigInteger a, BigInteger b) => a / b;
    public static BigInteger remainder(this BigInteger a, BigInteger b) => a % b;
    public static BigInteger and(this BigInteger a, BigInteger b) => a & b;
    public static BigInteger or(this BigInteger a, BigInteger b) => a | b;
    public static BigInteger xor(this BigInteger a, BigInteger b) => a ^ b;
    public static BigInteger not(this BigInteger a) => ~a;
    public static BigInteger shiftLeft(this BigInteger a, int n) => a << n;
    public static BigInteger shiftRight(this BigInteger a, int n) => a >> n;
    public static int compareTo(this BigInteger a, BigInteger b) => a.CompareTo(b);
    public static long longValue(this BigInteger a) => (long)a;
    public static int intValue(this BigInteger a) => (int)a;
    public static int bitLength(this BigInteger a) => (int)a.GetBitLength();

    // Primitive extensions
    public static int compareTo(this long a, long b) => a.CompareTo(b);
    public static int compare(this long a, long b) => a.CompareTo(b);
    public static long remainderUnsigned(this long a, long b) => (long)((ulong)a % (ulong)b);
    public static long divideUnsigned(this long a, long b) => (long)((ulong)a / (ulong)b);
    public static int compareUnsigned(this long a, long b) => ((ulong)a).CompareTo((ulong)b);
    public static string toHexString(this long a) => ((ulong)a).ToString("x");
    public static string toHexString(this int a) => ((uint)a).ToString("x");
}

#endregion
