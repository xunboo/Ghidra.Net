using System.Numerics;

namespace ghidra.util;

/**
 * Stateless helper classes with static singleton instances that contain methods to convert
 * Java numeric types to and from their raw form in a byte array.
 */
public interface DataConverter
{
    /**
     * Returns the correct DataConverter static instance for the requested endian-ness.
     * 
     * @param isBigEndian boolean flag, true means big endian
     * @return static DataConverter instance
     */
    public static DataConverter getInstance(bool isBigEndian)
    {
        return isBigEndian ? BigEndianDataConverter.INSTANCE : LittleEndianDataConverter.INSTANCE;
    }

    /**
     * Returns the endianness of this DataConverter instance.
     * 
     * @return boolean flag, true means big-endian
     */
    public virtual bool isBigEndian()
    {
        return this is BigEndianDataConverter;
    }

    public virtual short getShort(byte[] b)
    {
        return getShort(b, 0);
    }

    short getShort(byte[] b, int offset);

    public virtual int getInt(byte[] b)
    {
        return getInt(b, 0);
    }

    int getInt(byte[] b, int offset);

    public virtual long getLong(byte[] b)
    {
        return getLong(b, 0);
    }

    long getLong(byte[] b, int offset);

    public virtual long getValue(byte[] b, int size)
    {
        return getValue(b, 0, size);
    }

    long getValue(byte[] b, int offset, int size);

    public virtual BigInteger getBigInteger(byte[] b, int size, bool signed)
    {
        return getBigInteger(b, 0, size, signed);
    }

    BigInteger getBigInteger(byte[] b, int offset, int size, bool signed);

    public virtual void putShort(byte[] b, short value)
    {
        putShort(b, 0, value);
    }

    void putShort(byte[] b, int offset, short value);

    public virtual void putInt(byte[] b, int value)
    {
        putInt(b, 0, value);
    }

    void putInt(byte[] b, int offset, int value);

    public virtual void putLong(byte[] b, long value)
    {
        putLong(b, 0, value);
    }

    void putLong(byte[] b, int offset, long value);

    void putValue(long value, int size, byte[] b, int offset);

    byte[] getBytes(short value);

    byte[] getBytes(int value);

    byte[] getBytes(long value);

    byte[] getBytes(BigInteger value, int size);
}
