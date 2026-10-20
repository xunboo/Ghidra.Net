using ghidra.util.exception;

namespace ghidra.util.task;

/**
 * A dummy/stub implementation of TaskMonitor.
 */
public class StubTaskMonitor : TaskMonitor
{
    private volatile bool _cancelled;
    private string _message = string.Empty;
    private long _progress;
    private long _maximum = 100;

    public bool isCancelled() => _cancelled;

    public void checkCancelled()
    {
        if (_cancelled)
        {
            throw new CancelledException();
        }
    }

    public void setMessage(string message)
    {
        _message = message ?? string.Empty;
    }

    public string getMessage() => _message;

    public void setProgress(long value)
    {
        _progress = value;
    }

    public void initialize(long max)
    {
        _maximum = max;
        _progress = 0;
    }

    public void setMaximum(long max)
    {
        _maximum = max;
    }

    public long getMaximum() => _maximum;

    public long getProgress() => _progress;

    private readonly List<CancelledListener> _listeners = new();

    public void addCancelledListener(CancelledListener listener)
    {
        lock (_listeners) { _listeners.Add(listener); }
    }

    public void removeCancelledListener(CancelledListener listener)
    {
        lock (_listeners) { _listeners.Remove(listener); }
    }

    public void cancel()
    {
        _cancelled = true;
        List<CancelledListener> copy;
        lock (_listeners) { copy = new List<CancelledListener>(_listeners); }
        foreach (var l in copy) { l.cancelled(); }
    }

    public void clearCancelled()
    {
        _cancelled = false;
    }

    private volatile bool _cancelEnabled = true;

    public void setCancelEnabled(bool enable) => _cancelEnabled = enable;

    public bool isCancelEnabled() => _cancelEnabled;
}
