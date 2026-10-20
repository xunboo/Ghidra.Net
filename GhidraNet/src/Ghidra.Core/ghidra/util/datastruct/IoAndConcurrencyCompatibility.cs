namespace ghidra.util.datastruct;

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

#region IO Compatibility (JavaFile, Streams, Readers/Writers)

public class JavaFile
{
    private readonly string _path;

    public JavaFile(string pathname) => _path = pathname ?? throw new ArgumentNullException(nameof(pathname));
    public JavaFile(string? parent, string child) => _path = string.IsNullOrEmpty(parent) ? child : Path.Combine(parent, child);
    public JavaFile(JavaFile? parent, string child) : this(parent?._path, child) { }

    public bool exists() => System.IO.File.Exists(_path) || Directory.Exists(_path);
    public bool isFile() => System.IO.File.Exists(_path);
    public bool isDirectory() => Directory.Exists(_path);
    public string getName() => Path.GetFileName(_path);
    public string getPath() => _path;
    public string getAbsolutePath() => Path.GetFullPath(_path);
    public JavaFile? getParentFile()
    {
        var dir = Path.GetDirectoryName(_path);
        return dir != null ? new JavaFile(dir) : null;
    }
    public string? getParent() => Path.GetDirectoryName(_path);
    public long length()
    {
        var fi = new FileInfo(_path);
        return fi.Exists ? fi.Length : 0;
    }
    public long Length() => length();
    public long lastModified()
    {
        var fi = new FileInfo(_path);
        return fi.Exists ? new DateTimeOffset(fi.LastWriteTimeUtc).ToUnixTimeMilliseconds() : 0;
    }
    public bool delete()
    {
        try
        {
            if (System.IO.File.Exists(_path)) { System.IO.File.Delete(_path); return true; }
            if (Directory.Exists(_path)) { Directory.Delete(_path, true); return true; }
            return false;
        }
        catch { return false; }
    }
    public void deleteOnExit() { }
    public bool mkdir()
    {
        try { Directory.CreateDirectory(_path); return true; } catch { return false; }
    }
    public bool mkdirs() => mkdir();
    public bool createNewFile()
    {
        try
        {
            if (exists()) return false;
            System.IO.File.Create(_path).Dispose();
            return true;
        }
        catch { return false; }
    }
    public JavaFile[]? listFiles()
    {
        if (!isDirectory()) return null;
        try
        {
            return Directory.GetFileSystemEntries(_path).Select(p => new JavaFile(p)).ToArray();
        }
        catch { return null; }
    }
    public string[]? list()
    {
        if (!isDirectory()) return null;
        try { return Directory.GetFileSystemEntries(_path).Select(Path.GetFileName).ToArray()!; } catch { return null; }
    }
    public JavaFile[]? listFiles(FileFilter? filter)
    {
        var files = listFiles();
        if (files == null || filter == null) return files;
        return files.Where(f => filter.accept(f)).ToArray();
    }
    public bool renameTo(JavaFile dest)
    {
        try
        {
            if (System.IO.File.Exists(_path))
            {
                if (System.IO.File.Exists(dest._path)) System.IO.File.Delete(dest._path);
                System.IO.File.Move(_path, dest._path);
                return true;
            }
            if (Directory.Exists(_path))
            {
                Directory.Move(_path, dest._path);
                return true;
            }
            return false;
        }
        catch { return false; }
    }
    public bool canRead() => exists();
    public bool canWrite() => exists();

    public static JavaFile createTempFile(string prefix, string suffix, JavaFile? directory = null)
    {
        string dir = directory?._path ?? Path.GetTempPath();
        if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
        string filename = $"{prefix}{Guid.NewGuid().ToString("N")[..8]}{suffix}";
        string fullPath = Path.Combine(dir, filename);
        System.IO.File.Create(fullPath).Dispose();
        return new JavaFile(fullPath);
    }
    public string getCanonicalPath() => Path.GetFullPath(_path);

    public override string ToString() => _path;
    public override bool Equals(object? obj) => obj is JavaFile f && string.Equals(_path, f._path, StringComparison.OrdinalIgnoreCase);
    public override int GetHashCode() => StringComparer.OrdinalIgnoreCase.GetHashCode(_path);
    public static implicit operator string(JavaFile f) => f._path;
    public static implicit operator JavaFile(string s) => new(s);
}

public interface FileFilter
{
    bool accept(JavaFile file);
}

public interface FilenameFilter
{
    bool accept(JavaFile dir, string name);
}

public interface Closeable : IDisposable
{
    void close();
    void IDisposable.Dispose() => close();
}

public class FileDescriptor
{
    private readonly FileStream _stream;
    public FileDescriptor(FileStream stream) => _stream = stream;
    public void sync() => _stream.Flush(true);
}

public class RandomAccessFile : DataInput, DataOutput, Closeable, IDisposable
{
    private readonly FileStream _stream;

    public RandomAccessFile(string path, string mode)
    {
        bool write = mode.Contains("w");
        _stream = new FileStream(path,
            write ? FileMode.OpenOrCreate : FileMode.Open,
            write ? FileAccess.ReadWrite : FileAccess.Read,
            FileShare.ReadWrite);
    }

    public RandomAccessFile(JavaFile file, string mode) : this(file.getPath(), mode) { }

    public void seek(long pos) => _stream.Seek(pos, SeekOrigin.Begin);
    public long getFilePointer() => _stream.Position;
    public long length() => _stream.Length;
    public long Length() => _stream.Length;
    public void setLength(long newLength) => _stream.SetLength(newLength);

    public int read() => _stream.ReadByte();
    public int read(byte[] b) => _stream.Read(b, 0, b.Length);
    public int read(byte[] b, int off, int len) => _stream.Read(b, off, len);

    public void readFully(byte[] b) => readFully(b, 0, b.Length);
    public void readFully(byte[] b, int off, int len)
    {
        int n = 0;
        while (n < len)
        {
            int count = _stream.Read(b, off + n, len - n);
            if (count <= 0) throw new EOFException();
            n += count;
        }
    }

    public int skipBytes(int n)
    {
        if (n <= 0) return 0;
        long pos = _stream.Position;
        long len = _stream.Length;
        long newPos = Math.Min(pos + n, len);
        _stream.Seek(newPos, SeekOrigin.Begin);
        return (int)(newPos - pos);
    }

    public bool readBoolean()
    {
        int ch = _stream.ReadByte();
        if (ch < 0) throw new EOFException();
        return ch != 0;
    }

    public byte readByte()
    {
        int ch = _stream.ReadByte();
        if (ch < 0) throw new EOFException();
        return (byte)ch;
    }

    public int readUnsignedByte()
    {
        int ch = _stream.ReadByte();
        if (ch < 0) throw new EOFException();
        return ch;
    }

    public short readShort()
    {
        int ch1 = _stream.ReadByte();
        int ch2 = _stream.ReadByte();
        if ((ch1 | ch2) < 0) throw new EOFException();
        return (short)((ch1 << 8) + ch2);
    }

    public int readUnsignedShort()
    {
        int ch1 = _stream.ReadByte();
        int ch2 = _stream.ReadByte();
        if ((ch1 | ch2) < 0) throw new EOFException();
        return (ch1 << 8) + ch2;
    }

    public char readChar() => (char)readUnsignedShort();

    public int readInt()
    {
        int ch1 = _stream.ReadByte();
        int ch2 = _stream.ReadByte();
        int ch3 = _stream.ReadByte();
        int ch4 = _stream.ReadByte();
        if ((ch1 | ch2 | ch3 | ch4) < 0) throw new EOFException();
        return (ch1 << 24) + (ch2 << 16) + (ch3 << 8) + ch4;
    }

    public long readLong()
    {
        return ((long)readInt() << 32) + (readInt() & 0xFFFFFFFFL);
    }

    public float readFloat()
    {
        int val = readInt();
        return BitConverter.Int32BitsToSingle(val);
    }

    public double readDouble()
    {
        long val = readLong();
        return BitConverter.Int64BitsToDouble(val);
    }

    public string readLine()
    {
        StringBuilder sb = new();
        int c;
        while ((c = _stream.ReadByte()) != -1)
        {
            if (c == '\n') break;
            if (c == '\r')
            {
                long cur = _stream.Position;
                int next = _stream.ReadByte();
                if (next != '\n' && next != -1)
                {
                    _stream.Seek(cur, SeekOrigin.Begin);
                }
                break;
            }
            sb.Append((char)c);
        }
        return sb.ToString();
    }

    public string readUTF()
    {
        int utflen = readUnsignedShort();
        byte[] bytes = new byte[utflen];
        readFully(bytes, 0, utflen);
        return Encoding.UTF8.GetString(bytes);
    }

    public void write(int b) => _stream.WriteByte((byte)b);
    public void write(byte[] b) => _stream.Write(b, 0, b.Length);
    public void write(byte[] b, int off, int len) => _stream.Write(b, off, len);

    public void writeBoolean(bool v) => _stream.WriteByte(v ? (byte)1 : (byte)0);
    public void writeByte(int v) => _stream.WriteByte((byte)v);
    public void writeShort(int v)
    {
        _stream.WriteByte((byte)((v >> 8) & 0xFF));
        _stream.WriteByte((byte)(v & 0xFF));
    }
    public void writeChar(int v) => writeShort(v);
    public void writeInt(int v)
    {
        _stream.WriteByte((byte)((v >> 24) & 0xFF));
        _stream.WriteByte((byte)((v >> 16) & 0xFF));
        _stream.WriteByte((byte)((v >> 8) & 0xFF));
        _stream.WriteByte((byte)(v & 0xFF));
    }
    public void writeLong(long v)
    {
        _stream.WriteByte((byte)((v >> 56) & 0xFF));
        _stream.WriteByte((byte)((v >> 48) & 0xFF));
        _stream.WriteByte((byte)((v >> 40) & 0xFF));
        _stream.WriteByte((byte)((v >> 32) & 0xFF));
        _stream.WriteByte((byte)((v >> 24) & 0xFF));
        _stream.WriteByte((byte)((v >> 16) & 0xFF));
        _stream.WriteByte((byte)((v >> 8) & 0xFF));
        _stream.WriteByte((byte)(v & 0xFF));
    }
    public void writeFloat(float v) => writeInt(BitConverter.SingleToInt32Bits(v));
    public void writeDouble(double v) => writeLong(BitConverter.DoubleToInt64Bits(v));
    public void writeBytes(string s)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(s);
        _stream.Write(bytes, 0, bytes.Length);
    }
    public void writeChars(string s)
    {
        foreach (char c in s) writeChar(c);
    }
    public void writeUTF(string str)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(str);
        writeShort(bytes.Length);
        _stream.Write(bytes, 0, bytes.Length);
    }

    public FileDescriptor getFD() => new FileDescriptor(_stream);

    public void close() => _stream.Dispose();
    public void Dispose() => _stream.Dispose();
}


public class PrintStream : IDisposable
{
    private readonly TextWriter _writer;
    public PrintStream(TextWriter writer) => _writer = writer;
    public PrintStream(Stream stream) => _writer = new StreamWriter(stream, leaveOpen: true);
    public void print(object? o) => _writer.Write(o);
    public void print(string? s) => _writer.Write(s);
    public void println() => _writer.WriteLine();
    public void println(object? o) => _writer.WriteLine(o);
    public void println(string? s) => _writer.WriteLine(s);
    public void flush() => _writer.Flush();
    public void close() => _writer.Dispose();
    public void Dispose() => _writer.Dispose();
}

public class InputStream : IDisposable
{
    protected Stream BaseStream { get; set; } = Stream.Null;
    public InputStream() { }
    public InputStream(Stream s) => BaseStream = s;
    public virtual int read() => BaseStream.ReadByte();
    public virtual int read(byte[] b) => BaseStream.Read(b, 0, b.Length);
    public virtual int read(byte[] b, int off, int len) => BaseStream.Read(b, off, len);
    public virtual long skip(long n) => BaseStream.Seek(n, SeekOrigin.Current);
    public virtual int available() => (int)Math.Max(0, BaseStream.Length - BaseStream.Position);
    public virtual void close() => BaseStream.Dispose();
    public void Dispose() => close();
    public Stream getBaseStream() => BaseStream;
}

public class BufferedInputStream : InputStream
{
    private readonly InputStream _in;
    public BufferedInputStream(InputStream @in) : base(@in.getBaseStream()) { _in = @in; }
    public BufferedInputStream(InputStream @in, int size) : base(new BufferedStream(@in.getBaseStream(), size)) { _in = @in; }
    public override int read() => _in.read();
    public override int read(byte[] b) => _in.read(b);
    public override int read(byte[] b, int off, int len) => _in.read(b, off, len);
    public override void close() => _in.close();
}

public class OutputStream : IDisposable
{
    protected Stream BaseStream { get; set; } = Stream.Null;
    public OutputStream() { }
    public OutputStream(Stream s) => BaseStream = s;
    public virtual void write(int b) => BaseStream.WriteByte((byte)b);
    public virtual void write(byte[] b) => BaseStream.Write(b, 0, b.Length);
    public virtual void write(byte[] b, int off, int len) => BaseStream.Write(b, off, len);
    public virtual void flush() => BaseStream.Flush();
    public virtual void close() => BaseStream.Dispose();
    public void Dispose() => close();
}

public class FileInputStream : InputStream
{
    public FileInputStream(string path) : base(System.IO.File.OpenRead(path)) { }
    public FileInputStream(JavaFile file) : base(System.IO.File.OpenRead(file.getPath())) { }
}

public class FileOutputStream : OutputStream
{
    public FileOutputStream(string path, bool append = false) : base(new FileStream(path, append ? FileMode.Append : FileMode.Create, FileAccess.Write)) { }
    public FileOutputStream(JavaFile file, bool append = false) : this(file.getPath(), append) { }
}

public class ByteArrayInputStream : InputStream
{
    public ByteArrayInputStream(byte[] buf) : base(new MemoryStream(buf)) { }
    public ByteArrayInputStream(byte[] buf, int offset, int length) : base(new MemoryStream(buf, offset, length)) { }
}

public class ByteArrayOutputStream : OutputStream
{
    private readonly MemoryStream _ms;
    public ByteArrayOutputStream() : this(new MemoryStream()) { }
    private ByteArrayOutputStream(MemoryStream ms) : base(ms) => _ms = ms;
    public byte[] toByteArray() => _ms.ToArray();
    public int size() => (int)_ms.Length;
    public override string ToString() => Encoding.UTF8.GetString(_ms.ToArray());
}

public class Reader : IDisposable
{
    protected TextReader BaseReader { get; set; } = TextReader.Null;
    public Reader() { }
    public Reader(TextReader r) => BaseReader = r;
    public virtual int read() => BaseReader.Read();
    public virtual int read(char[] cbuf, int off, int len) => BaseReader.Read(cbuf, off, len);
    public virtual void close() => BaseReader.Dispose();
    public void Dispose() => close();
}

public class Writer : IDisposable
{
    protected TextWriter BaseWriter { get; set; } = TextWriter.Null;
    public Writer() { }
    public Writer(TextWriter w) => BaseWriter = w;
    public virtual void write(int c) => BaseWriter.Write((char)c);
    public virtual void write(char[] cbuf, int off, int len) => BaseWriter.Write(cbuf, off, len);
    public virtual void write(string str) => BaseWriter.Write(str);
    public virtual void flush() => BaseWriter.Flush();
    public virtual void close() => BaseWriter.Dispose();
    public void Dispose() => close();
}

public class FileReader : Reader
{
    public FileReader(string path) : base(System.IO.File.OpenText(path)) { }
    public FileReader(JavaFile file) : base(System.IO.File.OpenText(file.getPath())) { }
}

public class FileWriter : Writer
{
    public FileWriter(string path, bool append = false) : base(new StreamWriter(path, append)) { }
    public FileWriter(JavaFile file, bool append = false) : this(file.getPath(), append) { }
}

public class BufferedReader : Reader
{
    public BufferedReader(Reader r) { BaseReader = r is FileReader fr ? fr.GetBaseReader() : new StringReader(""); }
    public BufferedReader(TextReader tr) : base(tr) { }
    public string? readLine() => BaseReader.ReadLine();
}

internal static class ReaderHelper
{
    public static TextReader GetBaseReader(this FileReader fr) => fr is { } ? System.IO.File.OpenText("") : TextReader.Null;
}

#endregion

#region Regex Compatibility (JavaPattern, JavaMatcher)

public class JavaPattern
{
    private readonly Regex _regex;
    private readonly string _pattern;
    private readonly int _flags;

    public const int CASE_INSENSITIVE = 0x02;
    public const int MULTILINE = 0x08;
    public const int DOTALL = 0x20;

    public JavaPattern(string pattern, int flags = 0)
    {
        _pattern = pattern;
        _flags = flags;
        var options = RegexOptions.Compiled;
        if ((flags & CASE_INSENSITIVE) != 0) options |= RegexOptions.IgnoreCase;
        if ((flags & MULTILINE) != 0) options |= RegexOptions.Multiline;
        if ((flags & DOTALL) != 0) options |= RegexOptions.Singleline;
        _regex = new Regex(pattern, options);
    }

    public static JavaPattern compile(string regex) => new(regex);
    public static JavaPattern compile(string regex, int flags) => new(regex, flags);
    public JavaMatcher matcher(string input) => new(_regex, input);
    public string[] split(string input) => _regex.Split(input);
    public string pattern() => _pattern;
    public int flags() => _flags;
    public override string ToString() => _pattern;
}

public class JavaMatcher
{
    private readonly Regex _regex;
    private readonly string _input;
    private Match? _currentMatch;
    private int _searchPos;

    public JavaMatcher(Regex regex, string input)
    {
        _regex = regex;
        _input = input;
        _searchPos = 0;
    }

    public bool matches()
    {
        _currentMatch = _regex.Match(_input);
        return _currentMatch.Success && _currentMatch.Index == 0 && _currentMatch.Length == _input.Length;
    }

    public bool find()
    {
        _currentMatch = _searchPos < _input.Length ? _regex.Match(_input, _searchPos) : Match.Empty;
        if (_currentMatch.Success)
        {
            _searchPos = _currentMatch.Index + Math.Max(1, _currentMatch.Length);
            return true;
        }
        return false;
    }

    public bool find(int start)
    {
        _searchPos = start;
        return find();
    }

    public string group() => _currentMatch?.Value ?? "";
    public string group(int groupNum) => _currentMatch?.Groups[groupNum].Value ?? "";
    public int groupCount() => (_currentMatch?.Groups.Count ?? 1) - 1;
    public int start() => _currentMatch?.Index ?? -1;
    public int start(int groupNum) => _currentMatch?.Groups[groupNum].Index ?? -1;
    public int end() => _currentMatch != null ? _currentMatch.Index + _currentMatch.Length : -1;
    public int end(int groupNum) => _currentMatch != null ? _currentMatch.Groups[groupNum].Index + _currentMatch.Groups[groupNum].Length : -1;
    public string replaceAll(string replacement) => _regex.Replace(_input, replacement);
    public string replaceFirst(string replacement) => _regex.Replace(_input, replacement, 1);
    public JavaMatcher reset() { _searchPos = 0; _currentMatch = null; return this; }
}

#endregion

#region Concurrency Compatibility (TimeUnit, Locks, Barriers, Atomics)

public enum TimeUnit
{
    NANOSECONDS,
    MICROSECONDS,
    MILLISECONDS,
    SECONDS,
    MINUTES,
    HOURS,
    DAYS
}

public static class TimeUnitExtensions
{
    public static TimeSpan toTimeSpan(this TimeUnit unit, long duration) => unit switch
    {
        TimeUnit.NANOSECONDS => TimeSpan.FromTicks(duration / 100),
        TimeUnit.MICROSECONDS => TimeSpan.FromMicroseconds(duration),
        TimeUnit.MILLISECONDS => TimeSpan.FromMilliseconds(duration),
        TimeUnit.SECONDS => TimeSpan.FromSeconds(duration),
        TimeUnit.MINUTES => TimeSpan.FromMinutes(duration),
        TimeUnit.HOURS => TimeSpan.FromHours(duration),
        TimeUnit.DAYS => TimeSpan.FromDays(duration),
        _ => TimeSpan.FromMilliseconds(duration)
    };

    public static long toMillis(this TimeUnit unit, long duration) => (long)unit.toTimeSpan(duration).TotalMilliseconds;
}

public class CyclicBarrier
{
    private readonly Barrier _barrier;
    public CyclicBarrier(int parties) => _barrier = new(parties);
    public CyclicBarrier(int parties, Action barrierAction) => _barrier = new(parties, _ => barrierAction());
    public int await() { _barrier.SignalAndWait(); return (int)_barrier.CurrentPhaseNumber; }
    public int await(long timeout, TimeUnit unit)
    {
        if (!_barrier.SignalAndWait(unit.toTimeSpan(timeout)))
            throw new TimeoutException();
        return (int)_barrier.CurrentPhaseNumber;
    }
}

public class AtomicBoolean
{
    private int _value;
    public AtomicBoolean(bool initialValue = false) => _value = initialValue ? 1 : 0;
    public bool get() => Volatile.Read(ref _value) == 1;
    public void set(bool newValue) => Volatile.Write(ref _value, newValue ? 1 : 0);
    public bool getAndSet(bool newValue) => Interlocked.Exchange(ref _value, newValue ? 1 : 0) == 1;
    public bool compareAndSet(bool expect, bool update) => Interlocked.CompareExchange(ref _value, update ? 1 : 0, expect ? 1 : 0) == (expect ? 1 : 0);
}

public class AtomicInteger
{
    private int _value;
    public AtomicInteger(int initialValue = 0) => _value = initialValue;
    public int get() => Volatile.Read(ref _value);
    public void set(int newValue) => Volatile.Write(ref _value, newValue);
    public int getAndIncrement() => Interlocked.Increment(ref _value) - 1;
    public int getAndDecrement() => Interlocked.Decrement(ref _value) + 1;
    public int incrementAndGet() => Interlocked.Increment(ref _value);
    public int decrementAndGet() => Interlocked.Decrement(ref _value);
    public int addAndGet(int delta) => Interlocked.Add(ref _value, delta);
    public int getAndAdd(int delta) => Interlocked.Add(ref _value, delta) - delta;
    public bool compareAndSet(int expect, int update) => Interlocked.CompareExchange(ref _value, update, expect) == expect;
}

public class AtomicLong
{
    private long _value;
    public AtomicLong(long initialValue = 0) => _value = initialValue;
    public long get() => Volatile.Read(ref _value);
    public void set(long newValue) => Volatile.Write(ref _value, newValue);
    public long getAndIncrement() => Interlocked.Increment(ref _value) - 1;
    public long getAndDecrement() => Interlocked.Decrement(ref _value) + 1;
    public long incrementAndGet() => Interlocked.Increment(ref _value);
    public long decrementAndGet() => Interlocked.Decrement(ref _value);
    public long addAndGet(long delta) => Interlocked.Add(ref _value, delta);
    public long getAndAdd(long delta) => Interlocked.Add(ref _value, delta) - delta;
    public bool compareAndSet(long expect, long update) => Interlocked.CompareExchange(ref _value, update, expect) == expect;
}

public class AtomicReference<T> where T : class?
{
    private T _value;
    public AtomicReference(T initialValue = default!) => _value = initialValue;
    public T get() => Volatile.Read(ref _value);
    public void set(T newValue) => Volatile.Write(ref _value, newValue);
    public T getAndSet(T newValue) => Interlocked.Exchange(ref _value, newValue);
    public bool compareAndSet(T expect, T update) => ReferenceEquals(Interlocked.CompareExchange(ref _value, update, expect), expect);
}

#endregion

#region Types & Collection Interfaces

public interface Collection<T> : Iterable<T>, ICollection<T>
{
    int size() => Count;
    bool isEmpty() => Count == 0;
    bool contains(T o) => Contains(o);
    bool add(T e) { Add(e); return true; }
    bool remove(T o) => Remove(o);
    bool addAll(Collection<T> c)
    {
        bool mod = false;
        foreach (var item in c) { Add(item); mod = true; }
        return mod;
    }
    void clear() => Clear();
    T[] toArray() => this.ToArray();
}

public class Set<T> : HashSet<T>, Collection<T>
{
    private class SetIterator : Iterator<T>
    {
        private readonly IEnumerator<T> enumerator;
        private bool hasNextChecked = false;
        private bool hasNextVal = false;
        public SetIterator(IEnumerable<T> coll) { enumerator = coll.GetEnumerator(); }
        public bool hasNext()
        {
            if (!hasNextChecked)
            {
                hasNextVal = enumerator.MoveNext();
                hasNextChecked = true;
            }
            return hasNextVal;
        }
        public T next()
        {
            if (!hasNextChecked) hasNextVal = enumerator.MoveNext();
            hasNextChecked = false;
            return enumerator.Current;
        }
    }

    public Set() : base() { }
    public Set(IEnumerable<T> collection) : base(collection) { }
    public Set(IEqualityComparer<T> comparer) : base(comparer) { }
    public Iterator<T> iterator() => new SetIterator(this);
    public int size() => Count;
    public bool isEmpty() => Count == 0;
    public bool add(T item) => Add(item);
    public bool remove(T item) => Remove(item);
    public bool contains(T item) => Contains(item);
    public bool addAll(IEnumerable<T> c) { bool mod = false; foreach (var x in c) if (Add(x)) mod = true; return mod; }
    public bool removeAll(IEnumerable<T> c) { bool mod = false; foreach (var x in c) if (Remove(x)) mod = true; return mod; }
    public bool retainAll(IEnumerable<T> c) { var set = new HashSet<T>(c); int before = Count; RemoveWhere(x => !set.Contains(x)); return Count != before; }
    public void clear() => Clear();
    public T[] toArray() => this.ToArray();
}

public static class Set
{
    public static Set<T> of<T>(params T[] items) => new(items);
}



public class Class<T>
{
    public Type Type { get; }
    public Class(Type type) => Type = type;
    public static implicit operator Type(Class<T> c) => c.Type;
    public static implicit operator Class<T>(Type t) => new(t);
    public string getName() => Type.Name;
    public string getSimpleName() => Type.Name;
    public T newInstance() => (T)Activator.CreateInstance(Type)!;
    public bool isAssignableFrom(Class<T> cls) => Type.IsAssignableFrom(cls.Type);
    public bool isAssignableFrom(Type cls) => Type.IsAssignableFrom(cls);
    public override string ToString() => Type.ToString();
    public override bool Equals(object? obj) => obj is Class<T> c ? Type.Equals(c.Type) : Type.Equals(obj);
    public override int GetHashCode() => Type.GetHashCode();
}

public interface Remote { }

public class Date
{
    private readonly long _time;
    public Date() => _time = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public Date(long time) => _time = time;
    public long getTime() => _time;
    public override string ToString() => DateTimeOffset.FromUnixTimeMilliseconds(_time).ToString();
}

public class SyncFailedException : IOException
{
    public SyncFailedException() : base("Sync failed") { }
    public SyncFailedException(string message) : base(message) { }
    public SyncFailedException(string message, Exception inner) : base(message, inner) { }
}

public class InterruptedException : Exception
{
    public InterruptedException() : base("Thread interrupted") { }
    public InterruptedException(string message) : base(message) { }
    public InterruptedException(string message, Exception inner) : base(message, inner) { }
}

public class RemoteException : IOException
{
    public RemoteException() : base() { }
    public RemoteException(string? message) : base(message) { }
    public RemoteException(string? message, Exception? inner) : base(message, inner) { }
    public Exception? getCause() => InnerException;
}

public class NoSuchObjectException : RemoteException
{
    public NoSuchObjectException() : base() { }
    public NoSuchObjectException(string? message) : base(message) { }
}

public class ConnectException : RemoteException
{
    public ConnectException() : base() { }
    public ConnectException(string? message) : base(message) { }
}

public interface AutoCloseable : IDisposable
{
    void close();
    void IDisposable.Dispose() => close();
}

public interface Logger
{
    void debug(object msg);
    void info(object msg);
    void warn(object msg);
    void warn(object msg, Exception? t);
    void error(object msg);
    void error(object msg, Exception? t);
}

public class LogManager
{
    private class SimpleLogger : Logger
    {
        private readonly string _name;
        public SimpleLogger(string name) => _name = name;
        public void debug(object msg) { }
        public void info(object msg) { }
        public void warn(object msg) { }
        public void warn(object msg, Exception? t = null) { }
        public void error(object msg) { }
        public void error(object msg, Exception? t = null) { }
    }

    public static Logger getLogger(Type type) => new SimpleLogger(type.Name);
    public static Logger getLogger(string name) => new SimpleLogger(name);
}

#endregion
