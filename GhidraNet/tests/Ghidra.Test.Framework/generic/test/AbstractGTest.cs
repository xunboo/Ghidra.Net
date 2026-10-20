namespace generic.test;

using System;
using System.IO;
using System.Reflection;
using ghidra.util.datastruct;
using org.junit;

public abstract class AbstractGTest
{
    public static bool BATCH_MODE = false;
    protected static bool PARALLEL_MODE = false;

    public static readonly int DEFAULT_WAIT_DELAY = 10;
    public static readonly int DEFAULT_WAIT_TIMEOUT = 2000;
    public static readonly int DEFAULT_WINDOW_TIMEOUT = DEFAULT_WAIT_TIMEOUT;
    protected static readonly int PRIVATE_LONG_WAIT_TIMEOUT = DEFAULT_WAIT_TIMEOUT * 5;

    private static string? _testDirectoryPath;

    public static string getTestDirectoryPath()
    {
        if (_testDirectoryPath == null)
        {
            _testDirectoryPath = Path.Combine(Path.GetTempPath(), "ghidra_test_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_testDirectoryPath);
        }
        return _testDirectoryPath;
    }

    public static JavaFile createTempFile(string prefix, string suffix)
    {
        string path = Path.Combine(getTestDirectoryPath(), $"{prefix}_{Guid.NewGuid():N}{suffix}");
        System.IO.File.WriteAllText(path, "");
        return new JavaFile(path);
    }

    public static JavaFile createTempDirectory(string prefix)
    {
        string path = Path.Combine(getTestDirectoryPath(), $"{prefix}_{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return new JavaFile(path);
    }

    public static void setInstanceField(string fieldName, object target, object? value)
    {
        var type = target.GetType();
        FieldInfo? field = null;
        while (type != null && field == null)
        {
            field = type.GetField(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            type = type.BaseType;
        }
        if (field == null)
        {
            throw new ArgumentException($"Field '{fieldName}' not found on '{target.GetType().FullName}'");
        }
        field.SetValue(target, value);
    }

    public static object? getInstanceField(string fieldName, object target)
    {
        var type = target.GetType();
        FieldInfo? field = null;
        while (type != null && field == null)
        {
            field = type.GetField(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            type = type.BaseType;
        }
        if (field == null)
        {
            throw new ArgumentException($"Field '{fieldName}' not found on '{target.GetType().FullName}'");
        }
        return field.GetValue(target);
    }

    public static void setStaticField(string fieldName, Type type, object? value)
    {
        var field = type.GetField(fieldName, BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
        if (field == null)
        {
            throw new ArgumentException($"Static field '{fieldName}' not found on '{type.FullName}'");
        }
        field.SetValue(null, value);
    }

    public static object? getStaticField(string fieldName, Type type)
    {
        var field = type.GetField(fieldName, BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic);
        if (field == null)
        {
            throw new ArgumentException($"Static field '{fieldName}' not found on '{type.FullName}'");
        }
        return field.GetValue(null);
    }

    public static int getRandomInt(int min, int max) => Random.Shared.Next(min, max);
    public static string getRandomString() => Guid.NewGuid().ToString("N");
}
