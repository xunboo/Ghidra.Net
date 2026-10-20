using ghidra.util.exception;

namespace ghidra.util.task;

/**
 * TaskMonitor provides an interface that allows potentially long running tasks to show
 * progress and check for user cancellation.
 */
public interface TaskMonitor
{
    public static readonly TaskMonitor DUMMY = new StubTaskMonitor();

    public static TaskMonitor dummyIfNull(TaskMonitor tm)
    {
        return tm ?? DUMMY;
    }

    public const int NO_PROGRESS_VALUE = -1;

    bool isCancelled();

    void checkCancelled();

    void setMessage(string message);

    string getMessage();

    void setProgress(long value);

    void initialize(long max);

    void setMaximum(long max);

    long getMaximum();

    long getProgress();

    void cancel();

    void clearCancelled();

    void addCancelledListener(CancelledListener listener);

    void removeCancelledListener(CancelledListener listener);

    void setCancelEnabled(bool enable);

    bool isCancelEnabled();
}
