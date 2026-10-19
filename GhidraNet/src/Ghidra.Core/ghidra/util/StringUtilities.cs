namespace ghidra.util;

using System;

public static class StringUtilities
{
    public static bool equals(string? s1, string? s2, bool caseSensitive)
    {
        if (s1 == null) return s2 == null;
        return string.Equals(s1, s2, caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase);
    }
}
