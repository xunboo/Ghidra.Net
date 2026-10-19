using ghidra.program.model.address;
using Xunit;

namespace Ghidra.Framework.SoftwareModeling.Tests;

public class AddressTests
{
    private readonly GenericAddressSpace _ram32 = new("ram", 32, AddressSpace.TYPE_RAM, 0);
    private readonly GenericAddressSpace _ram64 = new("ram", 64, AddressSpace.TYPE_RAM, 0);
    private readonly GenericAddressSpace _reg = new("register", 32, AddressSpace.TYPE_REGISTER, 1);

    [Fact]
    public void TestAddressFormatting()
    {
        Address addr32 = _ram32.getAddress(0x401000L);
        Assert.Equal("00401000", addr32.toString());

        Address addr64 = _ram64.getAddress(0x140001000L);
        Assert.Equal("140001000", addr64.toString());
        Assert.Equal("0000000140001000", addr64.toString(false, true));

        Address regAddr = _reg.getAddress(0x04L);
        Assert.Equal("register:00000004", regAddr.toString());
    }

    [Fact]
    public void TestAddressArithmetic()
    {
        Address baseAddr = _ram32.getAddress(0x1000L);
        Address nextAddr = baseAddr.add(0x20);

        Assert.Equal(0x1020L, nextAddr.getOffset());
        Assert.Equal(0x20, nextAddr.subtract(baseAddr));

        Address prevAddr = nextAddr.subtract(0x20);
        Assert.Equal(baseAddr, prevAddr);
    }

    [Fact]
    public void TestAddressWrapAround()
    {
        Address maxAddr = _ram32.getAddress(-1L);
        Address wrapped = maxAddr.addWrap(1);

        Assert.Equal(0x0L, wrapped.getOffset());
    }

    [Fact]
    public void TestAddressComparison()
    {
        Address a1 = _ram32.getAddress(0x1000L);
        Address a2 = _ram32.getAddress(0x2000L);
        Address a3 = _ram32.getAddress(0x1000L);

        Assert.True(a1.compareTo(a2) < 0);
        Assert.True(a2.compareTo(a1) > 0);
        Assert.True(a1.compareTo(a3) == 0);
        Assert.True(a1.Equals(a3));
    }

    [Fact]
    public void TestAddressRange()
    {
        Address start = _ram32.getAddress(0x1000L);
        Address end = _ram32.getAddress(0x10FFL);
        AddressRange range = new AddressRangeImpl(start, end);

        Assert.Equal(0x100L, range.getLength());
        Assert.True(range.contains(_ram32.getAddress(0x1050L)));
        Assert.False(range.contains(_ram32.getAddress(0x1100L)));
    }

    [Fact]
    public void TestAddressSetMerge()
    {
        AddressSet set = new AddressSet();

        // Add range [0x1000, 0x10ff]
        set.add(new AddressRangeImpl(_ram32.getAddress(0x1000L), _ram32.getAddress(0x10FFL)));
        Assert.Equal(1, set.getNumAddressRanges());
        Assert.Equal(0x100L, set.getNumAddresses());

        // Add adjacent range [0x1100, 0x11ff] -> Should automatically coalesce into one range [0x1000, 0x11ff]
        set.add(new AddressRangeImpl(_ram32.getAddress(0x1100L), _ram32.getAddress(0x11FFL)));
        Assert.Equal(1, set.getNumAddressRanges());
        Assert.Equal(0x200L, set.getNumAddresses());
        Assert.Equal(0x1000L, set.getMinAddress()!.getOffset());
        Assert.Equal(0x11FFL, set.getMaxAddress()!.getOffset());

        // Add disjoint range [0x2000, 0x2050]
        set.add(new AddressRangeImpl(_ram32.getAddress(0x2000L), _ram32.getAddress(0x2050L)));
        Assert.Equal(2, set.getNumAddressRanges());
    }

    [Fact]
    public void TestAddressFactoryParsing()
    {
        DefaultAddressFactory factory = new DefaultAddressFactory([_ram32, _reg, AddressSpace.OTHER_SPACE], _ram32);

        Address a1 = factory.getAddress("00401000");
        Assert.Equal(_ram32, a1.getAddressSpace());
        Assert.Equal(0x401000L, a1.getOffset());

        Address a2 = factory.getAddress("0x401000");
        Assert.Equal(0x401000L, a2.getOffset());

        Address a3 = factory.getAddress("register:0x10");
        Assert.Equal(_reg, a3.getAddressSpace());
        Assert.Equal(0x10L, a3.getOffset());

        Address a4 = factory.getAddress("OTHER:0x500");
        Assert.Equal(AddressSpace.OTHER_SPACE, a4.getAddressSpace());
        Assert.Equal(0x500L, a4.getOffset());
    }
}
