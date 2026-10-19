using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using Xunit;

namespace Ghidra.Core.Tests;

public class DecompilerIpcTests
{
    private static readonly byte[] CommandStart = [0, 0, 1, 2];
    private static readonly byte[] CommandEnd = [0, 0, 1, 3];
    private static readonly byte[] StringStart = [0, 0, 1, 14];
    private static readonly byte[] StringEnd = [0, 0, 1, 15];

    [Fact]
    public void TestDecompilerNativeProcessPipeCommunication()
    {
        // Find decompile.exe in runtimes/win-x64/native
        string currentDir = AppDomain.CurrentDomain.BaseDirectory;
        string? repoRoot = currentDir;
        while (repoRoot != null && !Directory.Exists(Path.Combine(repoRoot, "runtimes")))
        {
            repoRoot = Directory.GetParent(repoRoot)?.FullName;
        }

        Assert.NotNull(repoRoot);
        string decompileExe = Path.Combine(repoRoot!, "runtimes", "win-x64", "native", "decompile.exe");
        Assert.True(File.Exists(decompileExe), $"Native decompiler executable not found at: {decompileExe}");

        var psi = new ProcessStartInfo
        {
            FileName = decompileExe,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi);
        Assert.NotNull(process);
        Assert.False(process.HasExited);

        // Send a framed command packet: CommandStart + StringStart + "queryVersion" + StringEnd + CommandEnd
        using var stdin = process.StandardInput.BaseStream;
        using var stdout = process.StandardOutput.BaseStream;

        byte[] cmdName = Encoding.ASCII.GetBytes("queryVersion");
        stdin.Write(CommandStart);
        stdin.Write(StringStart);
        stdin.Write(cmdName);
        stdin.Write(StringEnd);
        stdin.Write(CommandEnd);
        stdin.Flush();

        // Read response header: 0, 0, 1, 6 (Command Response Header)
        byte[] buffer = new byte[64];
        int bytesRead = stdout.Read(buffer, 0, buffer.Length);
        Assert.True(bytesRead > 8, "Expected to receive response burst from decompile.exe");

        // Verify framing: starts with \0\0\1\6 (command response)
        Assert.Equal(0, buffer[0]);
        Assert.Equal(0, buffer[1]);
        Assert.Equal(1, buffer[2]);
        Assert.Equal(6, buffer[3]);

        // Cleanly terminate process
        process.Kill(entireProcessTree: true);
        process.WaitForExit(1000);
    }
}
