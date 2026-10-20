namespace utilities.util;

using ghidra.util.datastruct;

public static class FileUtilities
{
    public static bool deleteDir(JavaFile dir) => dir.delete();
}
