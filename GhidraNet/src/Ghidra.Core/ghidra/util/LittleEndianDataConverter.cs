using System.Buffers.Binary;
using System.Numerics;

namespace ghidra.util;

/**
 * Helper class to convert a byte array to primitives and primitives to a
 * byte array in Little endian.
 */
public class LittleEndianDataConverter : DataConverter
{
    public static readonly LittleEndianDataConverter INSTANCE = new LittleEndianDataConverter();

    public LittleEndianDataConverter()
    {
    }

    public short getShort(byte[] b, int offset)
    {
        return BinaryPrimitives.ReadInt16LittleEndian(b.AsSpan(offset, 2));
    }

    public int getInt(byte[] b, int offset)
    {
        return BinaryPrimitives.ReadInt32LittleEndian(b.AsSpan(offset, 4));
    }

    public long getLong(byte[] b, int offset)
    {
        return BinaryPrimitives.ReadInt64LittleEndian(b.AsSpan(offset, 8));
    }

    public long getValue(byte[] b, int offset, int size)
    {
        long val = 0;
        for (int i = size - 1; i >= 0; i--)
        {
            val = (val << 8) | (b[offset + i] & 0xFFL);
        }
        return val;
    }

    public BigInteger getBigInteger(byte[] b, int offset, int size, bool signed)
    {
        byte[] copy = new byte[size];
        Array.Copy(b, offset, copy, 0, size);
        return new BigInteger(copy, isUnsigned: !signed, isBigEndian: false);
    }

    public void putShort(byte[] b, int offset, short value)
    {
        BinaryPrimitives.WriteInt16LittleEndian(b.AsSpan(offset, 2), value);
    }

    public void putInt(byte[] b, int offset, int value)
    {
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(offset, 4), value);
    }

    public void putLong(byte[] b, int offset, long value)
    {
        BinaryPrimitives.WriteInt64LittleEndian(b.AsSpan(offset, 8), value);
    }

    public void putValue(long value, int size, byte[] b, int offset)
    {
        for (int i = 0; i < size; i++)
        {
            b[offset + i] = (byte)(value & 0xFF);
            value >>= 8;
        }
    }

    public byte[] getBytes(short value)
    {
        byte[] bytes = new byte[2];
        putShort(bytes, 0, value);
        return bytes;
    }

    public byte[] getBytes(int value)
    {
        byte[] bytes = new byte[4];
        putInt(bytes, 0, value);
        return bytes;
    }

    public byte[] getBytes(long value)
    {
        byte[] bytes = new byte[8];
        putLong(bytes, 0, value);
        return bytes;
    }
}
