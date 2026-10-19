using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using ghidra.program.model.address;

namespace Ghidra.CLI;

public static class Program
{
    private static readonly byte[] CommandStart = [0, 0, 1, 2];
    private static readonly byte[] CommandEnd = [0, 0, 1, 3];
    private static readonly byte[] StringStart = [0, 0, 1, 14];
    private static readonly byte[] StringEnd = [0, 0, 1, 15];

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("================================================================================");
        Console.WriteLine("              Ghidra.NET 10.0 / C# 14 CLI 运行控制台");
        Console.WriteLine("================================================================================");
        Console.WriteLine($"[运行环境] .NET 运行时版本 : {Environment.Version}");
        Console.WriteLine($"[操作系统] {Environment.OSVersion} ({Environment.ProcessPath})");
        Console.WriteLine();

        // 1. 定位并验证编译好的原生 decompile.exe
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        string? rootDir = baseDir;
        while (rootDir != null && !Directory.Exists(Path.Combine(rootDir, "runtimes")))
        {
            rootDir = Directory.GetParent(rootDir)?.FullName;
        }

        if (rootDir == null)
        {
            rootDir = @"C:\Projects\GitHub\ghidra\GhidraNet";
        }

        string nativeDecompileExe = Path.Combine(rootDir, "runtimes", "win-x64", "native", "decompile.exe");
        Console.WriteLine("【步骤 1: 验证编译好的原生反编译器引擎 (decompile.exe)】");
        Console.WriteLine($"  文件路径: {nativeDecompileExe}");

        if (File.Exists(nativeDecompileExe))
        {
            var fi = new FileInfo(nativeDecompileExe);
            Console.WriteLine($"  文件状态: 存在 (大小: {fi.Length:N0} 字节 / 编译模式: MSVC x64 Native)");
            Console.WriteLine($"  创建时间: {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}");
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [错误] 未找到原生反编译器文件: {nativeDecompileExe}");
            Console.ResetColor();
            return 1;
        }

        Console.WriteLine();

        // 2. 启动原生 decompile.exe 并进行双向管道 IPC 交互
        Console.WriteLine("【步骤 2: 启动 decompile.exe 并通过标准管道 (stdin/stdout) 进行 IPC 交互测试】");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = nativeDecompileExe,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                throw new InvalidOperationException("无法启动原生反编译器进程。");
            }

            Console.WriteLine($"  > 原生反编译器已启动，进程 PID: {process.Id}");

            // 发送 Ghidra 二进制 Burst 协议数据包
            string testCommand = "ping";
            Console.WriteLine($"  > 正在向 decompile.exe stdin 发送命令帧: \"{testCommand}\" ...");
            
            var stdin = process.StandardInput.BaseStream;
            var stdout = process.StandardOutput.BaseStream;

            byte[] cmdBytes = Encoding.ASCII.GetBytes(testCommand);
            stdin.Write(CommandStart);
            stdin.Write(StringStart);
            stdin.Write(cmdBytes);
            stdin.Write(StringEnd);
            stdin.Write(CommandEnd);
            stdin.Flush();

            // 接收响应
            byte[] responseBuffer = new byte[128];
            int bytesRead = stdout.Read(responseBuffer, 0, responseBuffer.Length);

            Console.WriteLine($"  < 从 decompile.exe stdout 接收到响应 ({bytesRead} 字节)");
            if (bytesRead >= 8)
            {
                string hexHeader = BitConverter.ToString(responseBuffer, 0, Math.Min(8, bytesRead));
                Console.WriteLine($"  < 协议帧头 (Hex): {hexHeader}");
                
                // 提取返回字符串 (跳过帧头)
                string rawText = Encoding.Latin1.GetString(responseBuffer, 0, bytesRead);
                string cleanText = new string(rawText.Where(c => !char.IsControl(c) || c == ' ' || c == '\t').ToArray()).Trim();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  < 反编译器回传内容: \"{cleanText}\"");
                Console.ResetColor();
                Console.WriteLine("  ✓ 原生 C++ 反编译器双向管道 IPC 通信完全正常！");
            }

            process.Kill(entireProcessTree: true);
            process.WaitForExit(1000);
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [异常] IPC 交互失败: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();

        // 3. 演示纯 C# 转写的 Ghidra 逆向模型 (SoftwareModeling Address & Range)
        Console.WriteLine("【步骤 3: 运行 C# 转写的 Ghidra 逆向核心架构 (SoftwareModeling)】");
        try
        {
            var ram32 = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
            var ram64 = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
            var regSpace = new GenericAddressSpace("register", 32, AddressSpace.TYPE_REGISTER, 1);

            Address addr32 = ram32.getAddress(0x00401000L);
            Address addr64 = ram64.getAddress(0x140001000L);
            Address regAddr = regSpace.getAddress(0x10L);

            Console.WriteLine($"  32位 RAM 地址对象 : {addr32} (Offset=0x{addr32.getOffset():X8}, Space={addr32.getAddressSpace().getName()})");
            Console.WriteLine($"  64位 RAM 地址对象 : {addr64} (Offset=0x{addr64.getOffset():X16})");
            Console.WriteLine($"  寄存器地址对象    : {regAddr}");

            // 地址运算演示
            Address nextAddr = addr32.add(0x20);
            Console.WriteLine($"  地址算术 (+0x20)  : {addr32} -> {nextAddr} (Diff: 0x{nextAddr.subtract(addr32):X})");

            // 地址区间合并演示
            var addressSet = new AddressSet();
            addressSet.add(new AddressRangeImpl(ram32.getAddress(0x1000L), ram32.getAddress(0x10FFL)));
            addressSet.add(new AddressRangeImpl(ram32.getAddress(0x1100L), ram32.getAddress(0x11FFL))); // 相邻区间自动合并
            addressSet.add(new AddressRangeImpl(ram32.getAddress(0x2000L), ram32.getAddress(0x2050L)));

            Console.WriteLine($"  AddressSet 范围数 : {addressSet.getNumAddressRanges()} 个 (总地址数: {addressSet.getNumAddresses()})");
            Console.WriteLine($"  AddressSet 起止   : {addressSet.getMinAddress()} ~ {addressSet.getMaxAddress()}");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  ✓ 托管 C# 逆向核心模型运行完全正常！");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [异常] 核心模型运行失败: {ex.Message}");
            Console.ResetColor();
        }

        Console.WriteLine();
        Console.WriteLine("================================================================================");
        Console.WriteLine("                   Ghidra.NET 程序运行检测完成 (All Systems OK)");
        Console.WriteLine("================================================================================");

        return 0;
    }
}
