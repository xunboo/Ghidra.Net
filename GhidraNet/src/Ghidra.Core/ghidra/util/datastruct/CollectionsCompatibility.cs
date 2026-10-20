namespace ghidra.util.datastruct;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Provides 1:1 compatibility with Java's java.util.Iterator interface while bridging to C# IEnumerator.
/// </summary>
public interface Iterator<T> : IEnumerator<T>
{
    bool hasNext();
    T next();
    void remove() { }

    object IEnumerator.Current => next()!;
    T IEnumerator<T>.Current => next()!;
    bool IEnumerator.MoveNext() => hasNext();
    void IEnumerator.Reset() => throw new NotSupportedException();
    void IDisposable.Dispose() { }
}

/// <summary>
/// Provides 1:1 compatibility with Java's java.util.ListIterator interface.
/// </summary>
public interface ListIterator<T> : Iterator<T>
{
    bool hasPrevious();
    T previous();
    int nextIndex();
    int previousIndex();
    void set(T e) { }
    void add(T e) { }
}

/// <summary>
/// Provides 1:1 compatibility with Java's java.lang.Iterable interface while bridging to C# IEnumerable.
/// </summary>
public interface Iterable<T> : IEnumerable<T>
{
    Iterator<T> iterator();
    IEnumerator<T> IEnumerable<T>.GetEnumerator() => iterator();
    IEnumerator IEnumerable.GetEnumerator() => iterator();
}

/// <summary>
/// Provides 1:1 compatibility with Java's java.util.Comparator interface while bridging to C# IComparer.
/// </summary>
public static class Comparator
{
    private class NaturalOrderComparator<T> : Comparator<T>
    {
        public int compare(T o1, T o2) => Comparer<T>.Default.Compare(o1, o2);
    }

    public static Comparator<T> naturalOrder<T>() => new NaturalOrderComparator<T>();
}

public interface Comparator<T> : IComparer<T>
{
    int compare(T o1, T o2);
    int IComparer<T>.Compare(T? x, T? y) => compare(x!, y!);
}

/// <summary>
/// Provides 1:1 compatibility with Java's java.lang.Comparable interface while bridging to C# IComparable.
/// </summary>
public interface Comparable<T> : IComparable<T>
{
    int compareTo(T o);
    int IComparable<T>.CompareTo(T? other) => compareTo(other!);
}

public interface Entry<K, V>
{
    K getKey();
    V getValue();
    V setValue(V value);
}

public static class Map
{
    public interface Entry<K, V> : ghidra.util.datastruct.Entry<K, V>
    {
    }
}

public class Map<K, V> : Dictionary<K, V> where K : notnull
{
    public Map() : base() { }
    public Map(IDictionary<K, V> dictionary) : base(dictionary) { }
    public virtual V? get(K key) => TryGetValue(key, out var val) ? val : default;
    public virtual V? put(K key, V val) { var old = get(key); this[key] = val; return old; }
    public virtual V putIfAbsent(K key, V val)
    {
        if (!ContainsKey(key))
        {
            this[key] = val;
            return val;
        }
        return this[key];
    }
    public virtual V computeIfAbsent(K key, Func<K, V> mappingFunction)
    {
        if (!ContainsKey(key))
        {
            var val = mappingFunction(key);
            this[key] = val;
            return val;
        }
        return this[key];
    }
    public virtual void putAll(IDictionary<K, V> other)
    {
        foreach (var kvp in other) this[kvp.Key] = kvp.Value;
    }
    public class EntryImpl : Map.Entry<K, V>
    {
        private readonly K _key;
        private V _value;
        public EntryImpl(K key, V value) { _key = key; _value = value; }
        public K getKey() => _key;
        public V getValue() => _value;
        public V setValue(V value) { var old = _value; _value = value; return old; }
    }
    public virtual Set<Map.Entry<K, V>> entrySet()
    {
        var s = new Set<Map.Entry<K, V>>();
        foreach (var kvp in this) s.Add(new EntryImpl(kvp.Key, kvp.Value));
        return s;
    }
    public virtual V? remove(K key)
    {
        if (TryGetValue(key, out var old))
        {
            Remove(key);
            return old;
        }
        return default;
    }
    public bool containsKey(K key) => ContainsKey(key);
    public bool isEmpty() => Count == 0;
    public int size() => Count;
    public ICollection<V> values() => Values;
    public ICollection<K> keySet() => Keys;
}


public enum NodeColor
{
    RED,
    BLACK
}

public class NoSuchElementException : InvalidOperationException
{
    public NoSuchElementException() : base() { }
    public NoSuchElementException(string? message) : base(message) { }
    public NoSuchElementException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class IllegalArgumentException : ArgumentException
{
    public IllegalArgumentException() : base() { }
    public IllegalArgumentException(string? message) : base(message) { }
    public IllegalArgumentException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class IllegalStateException : InvalidOperationException
{
    public IllegalStateException() : base() { }
    public IllegalStateException(string? message) : base(message) { }
    public IllegalStateException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class UnsupportedOperationException : NotSupportedException
{
    public UnsupportedOperationException() : base() { }
    public UnsupportedOperationException(string? message) : base(message) { }
    public UnsupportedOperationException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class IndexOutOfBoundsException : ArgumentOutOfRangeException
{
    public IndexOutOfBoundsException() : base() { }
    public IndexOutOfBoundsException(string? message) : base(message) { }
    public IndexOutOfBoundsException(string? message, Exception? innerException) : base(message, innerException) { }
}

public class NullPointerException : NullReferenceException
{
    public NullPointerException() : base() { }
    public NullPointerException(string? message) : base(message) { }
    public NullPointerException(string? message, Exception? innerException) : base(message, innerException) { }
}

public static class Collections
{
    public static List<T> emptyList<T>() => new();
    public static HashSet<T> emptySet<T>() => new();
    public static Dictionary<K, V> emptyMap<K, V>() where K : notnull => new();
    public static ICollection<T> unmodifiableCollection<T>(ICollection<T> c) => c;
    public static List<T> unmodifiableList<T>(List<T> list) => list;
    public static ISet<T> unmodifiableSet<T>(ISet<T> set) => set;
    public static IDictionary<K, V> unmodifiableMap<K, V>(IDictionary<K, V> map) => map;
    public static void sort<T>(List<T> list) => list.Sort();
    public static void sort<T>(List<T> list, IComparer<T> c) => list.Sort(c);
    public static void reverse<T>(List<T> list) => list.Reverse();
    public static int binarySearch<T>(List<T> list, T key) => list.BinarySearch(key);
    public static int binarySearch<T>(List<T> list, T key, IComparer<T> c) => list.BinarySearch(key, c);
}

public static class Arrays
{
    public static List<T> asList<T>(params T[] a) => new(a);
    public static void fill<T>(T[] a, T val) => Array.Fill(a, val);
    public static void fill<T>(T[] a, int fromIndex, int toIndex, T val) => Array.Fill(a, val, fromIndex, toIndex - fromIndex);
    public static T[] copyOf<T>(T[] original, int newLength)
    {
        T[] copy = new T[newLength];
        Array.Copy(original, copy, Math.Min(original.Length, newLength));
        return copy;
    }
    public static T[] copyOfRange<T>(T[] original, int from, int to)
    {
        int newLength = to - from;
        T[] copy = new T[newLength];
        Array.Copy(original, from, copy, 0, Math.Min(original.Length - from, newLength));
        return copy;
    }
    public static bool equals<T>(T[]? a, T[]? a2)
    {
        if (ReferenceEquals(a, a2)) return true;
        if (a == null || a2 == null || a.Length != a2.Length) return false;
        return a.SequenceEqual(a2);
    }
    public static int hashCode<T>(T[]? a)
    {
        if (a == null) return 0;
        int result = 1;
        foreach (var element in a)
        {
            result = 31 * result + (element == null ? 0 : element.GetHashCode());
        }
        return result;
    }
    public static void sort<T>(T[] a) => Array.Sort(a);
    public static void sort<T>(T[] a, IComparer<T> c) => Array.Sort(a, c);
    public static int binarySearch<T>(T[] a, T key) => Array.BinarySearch(a, key);
}

public static class Spliterator
{
    public const int DISTINCT = 0x00000001;
    public const int SORTED = 0x00000004;
    public const int ORDERED = 0x00000010;
    public const int SIZED = 0x00000040;
    public const int NONNULL = 0x00000100;
    public const int IMMUTABLE = 0x00000400;
    public const int CONCURRENT = 0x00001000;
    public const int SUBSIZED = 0x00004000;
}

public interface Spliterator<T>
{
}

public static class Spliterators
{
    public static Spliterator<T> spliterator<T>(Iterator<T> iterator, long size, int characteristics) => null!;
}

public interface Stream<T> : IEnumerable<T>
{
    List<T> toList() => this.ToList();
    long count() => this.Count();
}

public class StreamImpl<T> : Stream<T>
{
    private readonly IEnumerable<T> _enumerable;
    public StreamImpl(IEnumerable<T> enumerable) { _enumerable = enumerable; }
    public IEnumerator<T> GetEnumerator() => _enumerable.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => _enumerable.GetEnumerator();
}

public static class StreamExtensions
{
    public static Stream<T> stream<T>(this IEnumerable<T> source) => new StreamImpl<T>(source);
}

public static class StreamSupport
{
    public static Stream<T> stream<T>(Spliterator<T> spliterator, bool parallel) => null!;
}

public interface Serializable { }

public class RuntimeException : Exception
{
    public RuntimeException() : base() { }
    public RuntimeException(string? message) : base(message) { }
    public RuntimeException(string? message, Exception? innerException) : base(message, innerException) { }
}

public static class EmptyListIterator
{
    public static readonly dynamic INSTANCE = null!;
}

public class EnumerableIterator<T> : Iterator<T>
{
    private readonly IEnumerator<T> _enumerator;
    private bool _hasAdvanced;
    private bool _hasMore;

    public EnumerableIterator(IEnumerable<T> source)
    {
        _enumerator = source.GetEnumerator();
        _hasAdvanced = false;
        _hasMore = false;
    }

    public bool hasNext()
    {
        if (!_hasAdvanced)
        {
            _hasMore = _enumerator.MoveNext();
            _hasAdvanced = true;
        }
        return _hasMore;
    }

    public T next()
    {
        if (!hasNext()) throw new InvalidOperationException("No more elements");
        _hasAdvanced = false;
        return _enumerator.Current;
    }
}

public static class RandomExtensions
{
    public static void nextBytes(this Random random, byte[] bytes) => random.NextBytes(bytes);
    public static int nextInt(this Random random) => random.Next();
    public static int nextInt(this Random random, int bound) => random.Next(bound);
    public static long nextLong(this Random random) => random.NextInt64();
    public static double nextDouble(this Random random) => random.NextDouble();
    public static bool nextBoolean(this Random random) => random.Next(2) == 0;
}

public interface Enumeration<T>
{
    bool hasMoreElements();
    T nextElement();
}

public static class PrimitiveCompatibilityExtensions
{
    public static int intValue(this int val) => val;
    public static long longValue(this long val) => val;
    public static double doubleValue(this double val) => val;
    public static float floatValue(this float val) => val;
    public static short shortValue(this short val) => val;
    public static byte byteValue(this byte val) => val;

    public static Enumeration<TKey> keys<TKey, TValue>(this Dictionary<TKey, TValue> dict) where TKey : notnull
    {
        return new DictionaryKeysEnumeration<TKey, TValue>(dict.Keys.GetEnumerator());
    }

    private class DictionaryKeysEnumeration<TKey, TValue> : Enumeration<TKey> where TKey : notnull
    {
        private Dictionary<TKey, TValue>.KeyCollection.Enumerator _e;
        private bool _hasMore;
        private bool _advanced;
        public DictionaryKeysEnumeration(Dictionary<TKey, TValue>.KeyCollection.Enumerator e) { _e = e; }
        public bool hasMoreElements()
        {
            if (!_advanced) { _hasMore = _e.MoveNext(); _advanced = true; }
            return _hasMore;
        }
        public TKey nextElement()
        {
            if (!hasMoreElements()) throw new InvalidOperationException();
            _advanced = false;
            return _e.Current;
        }
    }
}

public static class ArrayExtensions
{
    public static T[] clone<T>(this T[] array) => (T[])array.Clone();
}

public class WeakSet<T> : IEnumerable<T> where T : class
{
    private readonly List<WeakReference<T>> _items = new();
    private readonly object _lock = new();

    public void add(T item)
    {
        if (item == null) return;
        lock (_lock)
        {
            cleanup();
            if (!contains(item))
            {
                _items.Add(new WeakReference<T>(item));
            }
        }
    }

    public bool remove(T item)
    {
        if (item == null) return false;
        lock (_lock)
        {
            for (int i = _items.Count - 1; i >= 0; i--)
            {
                if (_items[i].TryGetTarget(out var target) && ReferenceEquals(target, item))
                {
                    _items.RemoveAt(i);
                    return true;
                }
            }
            return false;
        }
    }

    public bool contains(T item)
    {
        lock (_lock)
        {
            foreach (var wr in _items)
            {
                if (wr.TryGetTarget(out var target) && ReferenceEquals(target, item))
                    return true;
            }
            return false;
        }
    }

    public int size()
    {
        lock (_lock)
        {
            cleanup();
            return _items.Count;
        }
    }

    public bool isEmpty() => size() == 0;

    public void clear()
    {
        lock (_lock) { _items.Clear(); }
    }

    private void cleanup()
    {
        for (int i = _items.Count - 1; i >= 0; i--)
        {
            if (!_items[i].TryGetTarget(out _))
            {
                _items.RemoveAt(i);
            }
        }
    }

    public IEnumerator<T> GetEnumerator()
    {
        List<T> alive = new();
        lock (_lock)
        {
            cleanup();
            foreach (var wr in _items)
            {
                if (wr.TryGetTarget(out var target))
                    alive.Add(target);
            }
        }
        return alive.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

public static class WeakDataStructureFactory
{
    public static WeakSet<T> createSingleThreadAccessWeakSet<T>() where T : class => new();
    public static WeakSet<T> createCopyOnReadWeakSet<T>() where T : class => new();
    public static WeakSet<T> createCopyOnWriteWeakSet<T>() where T : class => new();
}

public class StringTokenizer
{
    private readonly string[] _tokens;
    private int _index;
    public StringTokenizer(string str, string delimiters = " \t\n\r\f")
    {
        _tokens = str.Split(delimiters.ToCharArray(), StringSplitOptions.RemoveEmptyEntries);
        _index = 0;
    }
    public bool hasMoreTokens() => _index < _tokens.Length;
    public bool hasMoreElements() => hasMoreTokens();
    public object nextElement() => nextToken();
    public string nextToken() => _index < _tokens.Length ? _tokens[_index++] : throw new InvalidOperationException("No more tokens");
    public int countTokens() => Math.Max(0, _tokens.Length - _index);
}

public static class BigIntegerExtensions
{
    public static byte[] toByteArray(this System.Numerics.BigInteger val) => val.ToByteArray(isUnsigned: false, isBigEndian: true);
}

public static class TypeExtensions
{
    public static bool isAssignableFrom(this Type target, Type from) => target.IsAssignableFrom(from);
}



