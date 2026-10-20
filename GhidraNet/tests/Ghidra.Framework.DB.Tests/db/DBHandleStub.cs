namespace db;

using db.buffers;
using ghidra.util.datastruct;
using ghidra.util.task;
using File = ghidra.util.datastruct.JavaFile;

public class DBHandle
{
    public DBHandle() { }
    public DBHandle(int bufferSize) { }
    public void saveAs(BufferFile bf, bool b, TaskMonitor? monitor) { }
    public void saveAs(JavaFile f, bool b, TaskMonitor? monitor) { }
    public void close() { }
}

internal class NodeMgr
{
    internal static readonly byte CHAINED_BUFFER_INDEX_NODE = 8;
    internal static readonly byte CHAINED_BUFFER_DATA_NODE = 9;
}
