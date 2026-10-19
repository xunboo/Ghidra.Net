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

    public void cancel()
    {
        _cancelled = true;
    }

    public void clearCancelled()
    {
        _cancelled = false;
    }
}
