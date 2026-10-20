namespace ghidra.util;

using System;
using ghidra.util.datastruct;

public static class SystemUtilities
{
    public static bool getBooleanProperty(string property, bool defaultValue)
    {
        string? val = JavaSystem.getProperty(property);
        return val != null ? bool.TryParse(val, out var b) ? b : defaultValue : defaultValue;
    }

    public static string getProperty(string property, string defaultValue)
    {
        return JavaSystem.getProperty(property, defaultValue) ?? defaultValue;
    }

    public static bool isInTestingMode() => true;
    public static bool isInHeadlessMode() => true;
    public static bool isHeadless() => true;
    public static void runSwingLater(Action action) => action?.Invoke();
    public static void runSwing(Action action) => action?.Invoke();
    public static void assertThisIsTheSwingThread(string? msg = null) { }
    public static bool isEqual(object? a, object? b) => Equals(a, b);
    public static void assertTrue(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException("Assertion failed: " + message);
    }
}
