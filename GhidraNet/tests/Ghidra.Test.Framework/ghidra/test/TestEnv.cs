namespace ghidra.test;

using System;
using System.IO;

public class TestEnv : IDisposable
{
    private readonly string _projectName;
    private bool _disposed;

    public TestEnv() : this("GhidraTestProject")
    {
    }

    public TestEnv(string projectName)
    {
        _projectName = projectName;
    }

    public TestEnv(int timeoutMinutes, string projectName)
    {
        _projectName = projectName;
    }

    public object? getTool() => null;
    public object? getProject() => null;

    public dynamic? getPlugin(Type pluginClass)
    {
        try { return Activator.CreateInstance(pluginClass); }
        catch
        {
            var ctor = pluginClass.GetConstructors().FirstOrDefault();
            if (ctor != null)
            {
                var pars = new object?[ctor.GetParameters().Length];
                return ctor.Invoke(pars);
            }
            return null;
        }
    }
    public T? getPlugin<T>(Type pluginClass) where T : class => (T?)Activator.CreateInstance(pluginClass);
    public T? getPlugin<T>() where T : class => (T?)Activator.CreateInstance(typeof(T));

    public void showTool()
    {
    }

    public void close(object program)
    {
    }

    public object? openProgram(string path) => null;
    public object? openProgram(object program) => program;

    public void dispose()
    {
        Dispose();
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
