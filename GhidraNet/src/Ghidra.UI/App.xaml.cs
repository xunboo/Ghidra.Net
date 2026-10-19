using System;
using System.IO;
using System.Windows;

namespace Ghidra.UI;

public partial class App : Application
{
    private static readonly string LogFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "debug.log");

    public static void Log(string message)
    {
        try
        {
            File.AppendAllText(LogFile, $"[{DateTime.Now:HH:mm:ss.fff}] {message}\r\n");
        }
        catch { }
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        Log("App.OnStartup called");

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            Log($"Unhandled: {args.ExceptionObject}");
        };

        DispatcherUnhandledException += (s, args) =>
        {
            Log($"Dispatcher: {args.Exception}");
        };

        Exit += (s, args) =>
        {
            Log($"App.Exit: code={args.ApplicationExitCode}");
        };

        base.OnStartup(e);
        Log("App.OnStartup finished");
    }
}
