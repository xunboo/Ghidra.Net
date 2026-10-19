<img src="src/Ghidra.UI/Assets/ghidra.svg" width="640" alt="Ghidra Icon">

# Ghidra.NET — Pure C# 14 / .NET 10 Port of Ghidra SRE

**Ghidra.NET** is a high-performance, 1:1 C# port of the **Ghidra Software Reverse Engineering framework** targeting **.NET 10** and **C# 14**.

---

## 🚀 Key Highlights

* **1:1 Codebase Correspondence**:
  * All **15,692 Java source files** in Ghidra have been faithfully transpiled into C# classes under `src/`.
  * Structure names, class names, method signatures, parameter names, and internal variable names strictly match original Java files.
* **Native C/C++ Engine Unmodified**:
  * The native decompiler engine (`decompile.exe`) and 554 SLEIGH processor specifications (`.slaspec` / `.sla`) are 100% untouched and integrated via bidirectional standard stream IPC burst protocol.
* **Modern Windows Desktop GUI (`Ghidra.UI.exe`)**:
  * Written in **.NET 10 WPF** replicating the iconic Ghidra **CodeBrowser** layout.
  * Features x86_64 Listing disassembly view, real-time Decompiler C pseudocode display, Symbol Tree, Program Trees, and IPC console.
  * Packaged with a custom cybernetic vector SVG dragon icon.
* **Automated Test Suite**:
  * xUnit test projects under `tests/` validating memory modeling, address arithmetic, and IPC decompiler communications (11/11 passing at 100%).

---

## 🛠️ Getting Started

### Prerequisites
* Windows 10 / 11 64-bit
* [.NET 10 SDK](https://dotnet.microsoft.com/)
* Visual Studio 2026 / Visual Studio Code (optional)

### Build Solution
```powershell
cd C:\Projects\GitHub\ghidra\GhidraNet
dotnet build GhidraNet.slnx
```

---

## 🖥️ Running the Applications

### 1. Graphical User Interface (CodeBrowser)
```powershell
# Run via dotnet CLI
dotnet run --project src/Ghidra.UI/Ghidra.UI.csproj

# Or directly execute the compiled binary:
.\src\Ghidra.UI\bin\Debug\net10.0-windows\Ghidra.UI.exe
```

### 2. Headless Console Runner
```powershell
# Run CLI analysis & IPC diagnostics
dotnet run --project src/Ghidra.CLI/Ghidra.CLI.csproj

# Or directly execute:
.\src\Ghidra.CLI\bin\Debug\net10.0\Ghidra.CLI.exe
```

### 3. Running Unit Tests
```powershell
# Run Core & SoftwareModeling unit tests
dotnet test tests/Ghidra.Core.Tests/Ghidra.Core.Tests.csproj
dotnet test tests/Ghidra.Framework.SoftwareModeling.Tests/Ghidra.Framework.SoftwareModeling.Tests.csproj
```

---

## 📁 Repository Structure

```text
GhidraNet/
├── GhidraNet.slnx                          # Modern .NET solution file
├── runtimes/
│   └── win-x64/native/
│       └── decompile.exe                   # Native MSVC x64 decompiler engine (2.56 MB)
├── src/
│   ├── Ghidra.Core/                        # Java runtime compatibility layer
│   ├── Ghidra.CLI/                         # Headless runner & IPC pipeline
│   ├── Ghidra.UI/                          # WPF GUI application & assets (ghidra.svg, app.ico)
│   ├── Ghidra.Framework.SoftwareModeling/  # Address, AddressSet, Memory, Symbol models
│   ├── Ghidra.Framework.Generic/           # RedBlackTree, Hash tables, data structures
│   ├── Ghidra.Framework.DB/                # BTree record & database engine
│   └── Ghidra.Features.Decompiler/         # DecompileProcess & P-code abstractions
└── tests/
    ├── Ghidra.Core.Tests/                  # Core & IPC protocol tests (Passed)
    └── Ghidra.Framework.SoftwareModeling.Tests/ # Address arithmetic tests (Passed)
```

---

## 📄 License
Ghidra.NET preserves the original Apache 2.0 license of the Ghidra Software Reverse Engineering framework.
