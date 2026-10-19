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
