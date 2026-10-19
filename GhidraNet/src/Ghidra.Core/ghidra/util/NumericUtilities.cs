using System.Globalization;
using System.Numerics;

namespace ghidra.util;

public static class NumericUtilities
{
    public static readonly BigInteger MAX_UNSIGNED_LONG = BigInteger.Parse("0ffffffffffffffff", NumberStyles.HexNumber);
    public static readonly BigInteger MAX_SIGNED_LONG = BigInteger.Parse("07fffffffffffffff", NumberStyles.HexNumber);
    public static readonly BigInteger MAX_UNSIGNED_INT = BigInteger.Parse("0ffffffff", NumberStyles.HexNumber);
    public const long MAX_UNSIGNED_INT32_AS_LONG = 0xFFFFFFFFL;

    public const string HEX_PREFIX_X = "0X";
    public const string HEX_PREFIX_x = "0x";

    public static ulong parseHexLong(string s)
    {
        if (s.StartsWith(HEX_PREFIX_x, StringComparison.OrdinalIgnoreCase))
        {
            s = s[2..];
        }
        return ulong.Parse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }

    public static string toHexString(long val) => ((ulong)val).ToString("x");
    public static string toHexString(int val) => ((uint)val).ToString("x");

    public static string toHexString(long val, int minDigits)
    {
        string hex = ((ulong)val).ToString("X");
        if (hex.Length < minDigits)
        {
            hex = hex.PadLeft(minDigits, '0');
        }
        return hex;
    }

    public static long bigIntegerToUnsignedLong(BigInteger value)
    {
        if (value <= MAX_SIGNED_LONG)
        {
            return (long)value;
        }
        return (long)(value - MAX_UNSIGNED_LONG) - 1;
    }

    public static BigInteger unsignedLongToBigInteger(long value)
    {
        if (value >= 0)
        {
            return new BigInteger(value);
        }
        return new BigInteger((ulong)value);
    }
}
