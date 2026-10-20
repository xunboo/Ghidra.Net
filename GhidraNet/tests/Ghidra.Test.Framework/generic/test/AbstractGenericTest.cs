namespace generic.test;

using System;
using System.IO;
using System.Reflection;
using ghidra.util.datastruct;
using org.junit;

public abstract class AbstractGenericTest : AbstractGTest, IDisposable
{
    private bool _hasFailed;
    private bool _disposed;

    public AbstractGenericTest()
    {
        InvokeLifecycleMethods<BeforeAttribute>("setUp");
    }

    public virtual void setUp()
    {
    }

    public virtual void tearDown()
    {
    }

    protected virtual void initializeSystemProperties()
    {
    }

    protected bool hasTestFailed() => _hasFailed;
    protected virtual void testFailed(Exception ex)
    {
        _hasFailed = true;
    }

    public void resetLogging()
    {
    }

    public void setLogLevel(string name, object level)
    {
    }

    private void InvokeLifecycleMethods<TAttr>(string defaultMethodName) where TAttr : Attribute
    {
        var type = GetType();
        var methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

        bool invokedExplicit = false;
        foreach (var m in methods)
        {
            if (m.GetCustomAttribute<TAttr>() != null)
            {
                m.Invoke(this, null);
                invokedExplicit = true;
            }
        }

        if (!invokedExplicit)
        {
            var defaultMethod = type.GetMethod(defaultMethodName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            if (defaultMethod != null && defaultMethod.DeclaringType != typeof(AbstractGenericTest))
            {
                defaultMethod.Invoke(this, null);
            }
        }
    }

    public virtual void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            try
            {
                InvokeLifecycleMethods<AfterAttribute>("tearDown");
            }
            catch
            {
                // ignore errors during teardown
            }
        }
        GC.SuppressFinalize(this);
    }
}
