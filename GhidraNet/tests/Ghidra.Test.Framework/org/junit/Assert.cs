namespace org.junit;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using ghidra.util.datastruct;

public static class Assert
{
    public static void assertTrue(bool condition) => assertTrue(null, condition);
    public static void assertTrue(string? message, bool condition)
    {
        if (!condition)
            throw new AssertionError(message ?? "Expected true but was false");
    }

    public static void assertFalse(bool condition) => assertFalse(null, condition);
    public static void assertFalse(string? message, bool condition)
    {
        if (condition)
            throw new AssertionError(message ?? "Expected false but was true");
    }

    public static void assertEquals(object? expected, object? actual) => assertEquals(null, expected, actual);
    public static void assertEquals(string? message, object? expected, object? actual)
    {
        if (expected == null && actual == null) return;
        if (expected == null || actual == null)
            throw new AssertionError((message != null ? message + ": " : "") + $"Expected '{expected}' but was '{actual}'");

        if (Equals(expected, actual)) return;

        if (expected is string es && actual is string as_)
        {
            if (es.Replace("\r\n", "\n") == as_.Replace("\r\n", "\n")) return;
        }

        // Numeric loose equality (e.g. boxed int vs long vs short)
        if (IsNumeric(expected) && IsNumeric(actual))
        {
            try
            {
                decimal d1 = Convert.ToDecimal(expected);
                decimal d2 = Convert.ToDecimal(actual);
                if (d1 == d2) return;
            }
            catch { }
        }

        if (expected is System.Numerics.BigInteger biExp)
        {
            if (actual is System.Numerics.BigInteger biAct && biExp == biAct) return;
            if (actual is ulong ul && biExp == new System.Numerics.BigInteger(ul)) return;
            if (actual is long l && biExp == new System.Numerics.BigInteger(l)) return;
            if (IsNumeric(actual))
            {
                try { if (biExp == new System.Numerics.BigInteger(Convert.ToInt64(actual))) return; } catch { }
            }
        }
        if (actual is System.Numerics.BigInteger biActual)
        {
            if (expected is ulong ul && new System.Numerics.BigInteger(ul) == biActual) return;
            if (expected is long l && new System.Numerics.BigInteger(l) == biActual) return;
            if (IsNumeric(expected))
            {
                try { if (new System.Numerics.BigInteger(Convert.ToInt64(expected)) == biActual) return; } catch { }
            }
        }

        // Sequence equality for collections or arrays
        if (expected is IEnumerable eSeq && actual is IEnumerable aSeq && !(expected is string))
        {
            var eList = eSeq.Cast<object>().ToList();
            var aList = aSeq.Cast<object>().ToList();
            if (eList.Count == aList.Count)
            {
                bool match = true;
                for (int i = 0; i < eList.Count; i++)
                {
                    if (!Equals(eList[i], aList[i]))
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return;
            }
        }

        throw new AssertionError((message != null ? message + ": " : "") + $"Expected '{expected}' (type {expected?.GetType().Name}) but was '{actual}' (type {actual?.GetType().Name})");
    }

    private static bool IsNumeric(object value)
    {
        return value is sbyte or byte or short or ushort or int or uint or long or ulong or float or double or decimal;
    }

    public static void assertEquals(double expected, double actual, double delta) => assertEquals(null, expected, actual, delta);
    public static void assertEquals(string? message, double expected, double actual, double delta)
    {
        if (double.IsNaN(expected) && double.IsNaN(actual)) return;
        if (double.IsPositiveInfinity(expected) && double.IsPositiveInfinity(actual)) return;
        if (double.IsNegativeInfinity(expected) && double.IsNegativeInfinity(actual)) return;
        if (Math.Abs(expected - actual) > delta)
            throw new AssertionError((message != null ? message + ": " : "") + $"Expected {expected} (+/- {delta}) but was {actual}");
    }

    public static void assertEquals(float expected, float actual, float delta) => assertEquals(null, expected, actual, delta);
    public static void assertEquals(string? message, float expected, float actual, float delta)
    {
        if (float.IsNaN(expected) && float.IsNaN(actual)) return;
        if (float.IsPositiveInfinity(expected) && float.IsPositiveInfinity(actual)) return;
        if (float.IsNegativeInfinity(expected) && float.IsNegativeInfinity(actual)) return;
        if (Math.Abs(expected - actual) > delta)
            throw new AssertionError((message != null ? message + ": " : "") + $"Expected {expected} (+/- {delta}) but was {actual}");
    }

    public static void assertEquals(long expected, long actual) => assertEquals(null, (object)expected, (object)actual);
    public static void assertEquals(string? message, long expected, long actual) => assertEquals(message, (object)expected, (object)actual);
    public static void assertEquals(int expected, int actual) => assertEquals(null, (object)expected, (object)actual);
    public static void assertEquals(string? message, int expected, int actual) => assertEquals(message, (object)expected, (object)actual);

    public static void assertNotEquals(object? unexpected, object? actual) => assertNotEquals(null, unexpected, actual);
    public static void assertNotEquals(string? message, object? unexpected, object? actual)
    {
        if (Equals(unexpected, actual))
            throw new AssertionError((message != null ? message + ": " : "") + $"Unexpected value '{actual}'");
    }

    public static void assertNull(object? obj) => assertNull(null, obj);
    public static void assertNull(string? message, object? obj)
    {
        if (obj != null)
            throw new AssertionError((message != null ? message + ": " : "") + $"Expected null but was '{obj}'");
    }

    public static void assertNotNull(object? obj) => assertNotNull(null, obj);
    public static void assertNotNull(string? message, object? obj)
    {
        if (obj == null)
            throw new AssertionError((message != null ? message + ": " : "") + "Expected not null but was null");
    }

    public static void assertSame(object? expected, object? actual) => assertSame(null, expected, actual);
    public static void assertSame(string? message, object? expected, object? actual)
    {
        if (!ReferenceEquals(expected, actual))
            throw new AssertionError((message != null ? message + ": " : "") + $"Expected same instance but got '{expected}' and '{actual}'");
    }

    public static void assertNotSame(object? unexpected, object? actual) => assertNotSame(null, unexpected, actual);
    public static void assertNotSame(string? message, object? unexpected, object? actual)
    {
        if (ReferenceEquals(unexpected, actual))
            throw new AssertionError((message != null ? message + ": " : "") + "Expected different instances");
    }

    public static void assertArrayEquals(byte[]? expected, byte[]? actual) => assertArrayEquals(null, expected, actual);
    public static void assertArrayEquals(string? message, byte[]? expected, byte[]? actual)
    {
        if (expected == null && actual == null) return;
        if (expected == null || actual == null || !expected.SequenceEqual(actual))
            throw new AssertionError((message != null ? message + ": " : "") + "Byte arrays are not equal");
    }

    public static void assertArrayEquals(int[]? expected, int[]? actual) => assertArrayEquals(null, expected, actual);
    public static void assertArrayEquals(string? message, int[]? expected, int[]? actual)
    {
        if (expected == null && actual == null) return;
        if (expected == null || actual == null || !expected.SequenceEqual(actual))
            throw new AssertionError((message != null ? message + ": " : "") + "Int arrays are not equal");
    }

    public static void assertArrayEquals(long[]? expected, long[]? actual) => assertArrayEquals(null, expected, actual);
    public static void assertArrayEquals(string? message, long[]? expected, long[]? actual)
    {
        if (expected == null && actual == null) return;
        if (expected == null || actual == null || !expected.SequenceEqual(actual))
            throw new AssertionError((message != null ? message + ": " : "") + "Long arrays are not equal");
    }

    public static void assertArrayEquals(short[]? expected, short[]? actual) => assertArrayEquals(null, expected, actual);
    public static void assertArrayEquals(string? message, short[]? expected, short[]? actual)
    {
        if (expected == null && actual == null) return;
        if (expected == null || actual == null || !expected.SequenceEqual(actual))
            throw new AssertionError((message != null ? message + ": " : "") + "Short arrays are not equal");
    }

    public static void assertArrayEquals(object[]? expected, object[]? actual) => assertArrayEquals(null, expected, actual);
    public static void assertArrayEquals(string? message, object[]? expected, object[]? actual)
    {
        if (expected == null && actual == null) return;
        if (expected == null || actual == null || !expected.SequenceEqual(actual))
            throw new AssertionError((message != null ? message + ": " : "") + "Arrays are not equal");
    }

    public static void fail() => fail(null);
    public static void fail(string? message) => throw new AssertionError(message ?? "Test failed");

    public static T assertThrows<T>(Action action) where T : Exception
    {
        try
        {
            action();
        }
        catch (T ex)
        {
            return ex;
        }
        catch (Exception ex)
        {
            throw new AssertionError($"Expected {typeof(T).Name} but caught {ex.GetType().Name}: {ex.Message}");
        }
        throw new AssertionError($"Expected {typeof(T).Name} to be thrown, but nothing was thrown.");
    }
}
