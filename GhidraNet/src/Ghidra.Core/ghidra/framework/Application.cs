using System;
using System.IO;
using ghidra.util.datastruct;

namespace ghidra.framework;

public static class Application
{
    public static JavaFile createTempFile(string prefix, string suffix) => JavaFile.createTempFile(prefix, suffix);
    public static JavaFile getUserTempDirectory() => new JavaFile(Path.GetTempPath());
}
