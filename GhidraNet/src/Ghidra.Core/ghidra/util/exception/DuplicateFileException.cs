using System;
using System.IO;

namespace ghidra.util.exception;

public class DuplicateFileException : IOException
{
    public DuplicateFileException() : base() { }
    public DuplicateFileException(string message) : base(message) { }
    public DuplicateFileException(string message, Exception inner) : base(message, inner) { }
}
