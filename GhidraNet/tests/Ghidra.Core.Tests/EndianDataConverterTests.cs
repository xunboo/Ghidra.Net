using ghidra.util;
using ghidra.util.task;
using Xunit;

namespace Ghidra.Core.Tests;

public class DataConverterTests
{
    [Fact]
    public void TestLittleEndianDataConverter()
    {
        DataConverter conv = LittleEndianDataConverter.INSTANCE;
        byte[] bytes = [0x78, 0x56, 0x34, 0x12];

        int val = conv.getInt(bytes, 0);
        Assert.Equal(0x12345678, val);

        byte[] dest = new byte[4];
        conv.putInt(dest, 0, 0x12345678);
        Assert.Equal(bytes, dest);

        Assert.False(conv.isBigEndian());
    }

    [Fact]
    public void TestBigEndianDataConverter()
    {
        DataConverter conv = BigEndianDataConverter.INSTANCE;
        byte[] bytes = [0x12, 0x34, 0x56, 0x78];

        int val = conv.getInt(bytes, 0);
        Assert.Equal(0x12345678, val);

        byte[] dest = new byte[4];
        conv.putInt(dest, 0, 0x12345678);
        Assert.Equal(bytes, dest);

        Assert.True(conv.isBigEndian());
    }

    [Fact]
    public void TestTaskMonitorStub()
    {
        TaskMonitor monitor = TaskMonitor.DUMMY;
        Assert.False(monitor.isCancelled());
        monitor.checkCancelled(); // Should not throw

        StubTaskMonitor stub = new StubTaskMonitor();
        stub.initialize(50);
        stub.setProgress(25);
        Assert.Equal(50, stub.getMaximum());
        Assert.Equal(25, stub.getProgress());
    }
}
