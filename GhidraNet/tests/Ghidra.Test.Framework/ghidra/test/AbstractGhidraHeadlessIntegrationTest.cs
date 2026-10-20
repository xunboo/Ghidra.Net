namespace ghidra.test;

using System;
using System.IO;
using docking.test;
using generic.test;

public abstract class AbstractGhidraHeadlessIntegrationTest : AbstractDockingTest
{
    public static readonly string PROJECT_NAME = "GhidraTestProject";
    protected TestEnv? env;

    public AbstractGhidraHeadlessIntegrationTest() : base()
    {
    }

    public new static string getTestDirectoryPath()
    {
        string dir = Path.Combine(Path.GetTempPath(), "ghidra_test");
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        return dir;
    }

    public static bool deleteProject(string directory, string name)
    {
        try
        {
            string path = Path.Combine(directory, name + ".gpr");
            if (File.Exists(path)) File.Delete(path);
            string repDir = Path.Combine(directory, name + ".rep");
            if (Directory.Exists(repDir)) Directory.Delete(repDir, true);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
