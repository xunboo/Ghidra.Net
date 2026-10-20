namespace ghidra.util;

using System;

public static class Msg
{
    public static void trace(object? originator, object? message) { }
    public static void debug(object? originator, object? message) { }
    public static void info(object? originator, object? message) { }
    public static void warn(object? originator, object? message) => Console.Error.WriteLine($"[WARN] {originator}: {message}");
    public static void warn(object? originator, object? message, Exception? ex) => Console.Error.WriteLine($"[WARN] {originator}: {message}\n{ex}");
    public static void error(object? originator, object? message) => Console.Error.WriteLine($"[ERROR] {originator}: {message}");
    public static void error(object? originator, object? message, Exception? ex) => Console.Error.WriteLine($"[ERROR] {originator}: {message}\n{ex}");
    public static void showInfo(object? originator, object? parent, string title, object? message) { }
    public static void showWarn(object? originator, object? parent, string title, object? message) { }
    public static void showError(object? originator, object? parent, string title, object? message) { }
    public static void showError(object? originator, object? parent, string title, object? message, Exception? ex) { }
}
