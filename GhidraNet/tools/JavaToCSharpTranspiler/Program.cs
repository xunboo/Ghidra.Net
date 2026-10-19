using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace JavaToCSharpTranspiler;

public static class Program
{
    private static readonly string GhidraSourceDir = @"C:\Projects\GitHub\ghidra\Ghidra";
    private static readonly string GhidraNetTargetDir = @"C:\Projects\GitHub\ghidra\GhidraNet";
    private static readonly Regex TokenRegex = new(@"__PROT_TOKEN_(\d+)__", RegexOptions.Compiled);

    public static int Main(string[] args)
    {
        Console.WriteLine("=== Ghidra Java -> C# Automated Transpiler (Lexer-Protected v4) ===");
        var sw = Stopwatch.StartNew();

        if (!Directory.Exists(GhidraSourceDir))
        {
            Console.Error.WriteLine($"Source directory does not exist: {GhidraSourceDir}");
            return 1;
        }

        Console.WriteLine($"Scanning for Java source files in: {GhidraSourceDir} ...");
        var javaFiles = Directory.GetFiles(GhidraSourceDir, "*.java", SearchOption.AllDirectories);
        Console.WriteLine($"Discovered {javaFiles.Length} Java source files.");

        int processedCount = 0;
        int errorCount = 0;

        var targetProjects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Process files in parallel
        Parallel.ForEach(javaFiles, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, javaFile =>
        {
            try
            {
                var targetPath = ResolveTargetPath(javaFile, GhidraSourceDir, GhidraNetTargetDir, out string projectDir);
                if (!string.IsNullOrEmpty(projectDir))
                {
                    lock (targetProjects)
                    {
                        targetProjects.Add(projectDir);
                    }
                }

                string javaContent = File.ReadAllText(javaFile, Encoding.UTF8);
                string csharpContent = TranspileJavaToCSharp(javaContent, javaFile);

                var targetDir = Path.GetDirectoryName(targetPath)!;
                Directory.CreateDirectory(targetDir);

                File.WriteAllText(targetPath, csharpContent, Encoding.UTF8);

                int count = Interlocked.Increment(ref processedCount);
                if (count % 1000 == 0 || count == javaFiles.Length)
                {
                    Console.WriteLine($"Progress: {count}/{javaFiles.Length} files converted ({(count * 100.0 / javaFiles.Length):F1}%)...");
                }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref errorCount);
                Console.Error.WriteLine($"Error transpiling {javaFile}: {ex.Message}");
            }
        });

        Console.WriteLine($"Generating project files for {targetProjects.Count} detected modules...");
        foreach (var projDir in targetProjects)
        {
            EnsureCsprojExists(projDir);
        }

        sw.Stop();
        Console.WriteLine("==================================================");
        Console.WriteLine($"Transpilation completed in {sw.ElapsedMilliseconds} ms ({sw.Elapsed.TotalSeconds:F2} s).");
        Console.WriteLine($"Total processed: {processedCount}, Errors: {errorCount}");
        Console.WriteLine("==================================================");

        return errorCount == 0 ? 0 : 2;
    }

    public static string ResolveTargetPath(string javaFilePath, string sourceRoot, string targetRoot, out string projectDir)
    {
        string relPath = Path.GetRelativePath(sourceRoot, javaFilePath);
        string[] parts = relPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        int srcIndex = -1;
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].Equals("src", StringComparison.OrdinalIgnoreCase))
            {
                srcIndex = i;
                break;
            }
        }

        string projName;
        bool isTest = relPath.Contains(@"\test\", StringComparison.OrdinalIgnoreCase) ||
                      relPath.Contains(@"\test.slow\", StringComparison.OrdinalIgnoreCase);

        if (srcIndex >= 2)
        {
            projName = $"Ghidra.{parts[0]}.{parts[1]}";
            if (isTest) projName += ".Tests";
        }
        else if (parts.Length >= 2)
        {
            projName = $"Ghidra.{parts[0]}.{parts[1]}";
            if (isTest) projName += ".Tests";
        }
        else
        {
            projName = "Ghidra.Core";
        }

        string baseFolder = isTest ? "tests" : "src";
        string projRoot = Path.Combine(targetRoot, baseFolder, projName);
        projectDir = projRoot;

        string inPackageRelPath;
        int javaIdx = -1;
        for (int i = 0; i < parts.Length; i++)
        {
            if (parts[i].Equals("java", StringComparison.OrdinalIgnoreCase))
            {
                javaIdx = i;
                break;
            }
        }

        if (javaIdx >= 0 && javaIdx < parts.Length - 1)
        {
            inPackageRelPath = string.Join(Path.DirectorySeparatorChar, parts.Skip(javaIdx + 1));
        }
        else
        {
            inPackageRelPath = string.Join(Path.DirectorySeparatorChar, parts.Skip(Math.Min(2, parts.Length - 1)));
        }

        string csFileName = Path.ChangeExtension(inPackageRelPath, ".cs");
        return Path.Combine(projRoot, csFileName);
    }

    private static void EnsureCsprojExists(string projDir)
    {
        string projName = Path.GetFileName(projDir);
        string csprojPath = Path.Combine(projDir, $"{projName}.csproj");

        if (!File.Exists(csprojPath))
        {
            Directory.CreateDirectory(projDir);
            bool isTest = projName.EndsWith(".Tests", StringComparison.OrdinalIgnoreCase);

            string content = $@"<Project Sdk=""Microsoft.NET.Sdk"">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
  </PropertyGroup>
{(isTest ? @"  <ItemGroup>
    <PackageReference Include=""Microsoft.NET.Test.Sdk"" Version=""17.13.0"" />
    <PackageReference Include=""xunit"" Version=""2.9.3"" />
    <PackageReference Include=""xunit.runner.visualstudio"" Version=""3.0.2"" />
  </ItemGroup>" : "")}
</Project>
";
            File.WriteAllText(csprojPath, content, Encoding.UTF8);
        }
    }

    public static string TranspileJavaToCSharp(string javaCode, string fileName)
    {
        // 1. Separate code from comments and string literals using full lexical scanning
        var (codeWithoutProtectedTokens, protectedTokens) = ExtractProtectedTokens(javaCode);

        // 2. Transform package declaration -> namespace
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bpackage\s+([\w\.]+)\s*;", "namespace $1;");

        // 3. Transform imports
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bimport\s+static\s+([\w\.]+)\.([A-Za-z0-9_]+)\s*;", "using static $1;");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bimport\s+static\s+([\w\.]+)\.\*\s*;", "using static $1;");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bimport\s+([\w\.]+)\.\*\s*;", "using $1;");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bimport\s+([\w\.]+)\.([A-Za-z0-9_]+)\s*;", "using $1;");

        // Remove standard java package usings
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\busing\s+java\.[\w\.]+\s*;", "");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\busing\s+javax\.[\w\.]+\s*;", "");

        // 4. Try-With-Resources (must be run BEFORE keyword escaping or other transforms)
        codeWithoutProtectedTokens = TransformTryWithResources(codeWithoutProtectedTokens);

        // 5. Enhanced for loop: for (Type var : expr) -> foreach (Type var in expr)
        codeWithoutProtectedTokens = TransformEnhancedForLoops(codeWithoutProtectedTokens);

        // 6. Type declarations (class, record, interface) with generic constraints and inheritance
        codeWithoutProtectedTokens = TransformTypeDeclarations(codeWithoutProtectedTokens);

        // 6b. Rich enums with state, interfaces, or constructors -> classes
        codeWithoutProtectedTokens = TransformRichEnums(codeWithoutProtectedTokens);

        // 6c. Anonymous inner classes -> nested classes
        codeWithoutProtectedTokens = TransformAnonymousClasses(codeWithoutProtectedTokens);

        // 6d. Java annotations
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"@Deprecated(?:\s*\([^)]*\))?", "[Obsolete]");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"(@[A-Z][A-Za-z0-9_]*(\s*\([^\)]*\))?)", "/* $1 */");

        // 6e. Java static initializer blocks: static { ... } -> static ClassName() { ... }
        string mainClassName = Path.GetFileNameWithoutExtension(fileName);
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bstatic\s*\{", $"static {mainClassName}() {{");

        // 6f. Enclosing class this reference in inner classes: EnclosingClass.this -> this
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b[A-Za-z0-9_]+\.this\b", "this");

        // 6g. Generic methods: <T> ReturnType method() -> ReturnType method<T>()
        codeWithoutProtectedTokens = TransformGenericMethods(codeWithoutProtectedTokens);

        // 7. Throws removal on method declarations
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\)\s*throws\s+[A-Za-z0-9_,\s<>]+\{", ")\n    {");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\)\s*throws\s+[A-Za-z0-9_,\s<>]+\;", ");");

        // 8. Keywords & Identifiers escaping
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bbase\b", "@base");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bis\b", "@is");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bas\b", "@as");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bref\b", "@ref");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bstruct\b", "@struct");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bobject\b", "@object");

        // Method @lock declaration and call
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b(void|boolean|bool|byte|sbyte|short|ushort|int|uint|long|ulong|float|double|char|string|[A-Z][A-Za-z0-9_<>]*)\s+lock\s*\(", "$1 @lock(");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\.lock\s*\(", ".@lock(");

        // RedBlackEntry.NodeColor -> NodeColor
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bRedBlackEntry(?:\.NodeColor)?\.NodeColor\b", "NodeColor");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bRedBlackEntry<[^>]+>\.NodeColor\b", "NodeColor");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bRedBlackEntry\.NodeColor\b", "NodeColor");

        // Field 'iterator' in classes that implement Iterable / Iterator adapters (avoid CS0102)
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b(Iterator<[^>]+>\s+)iterator\s*;", "$1_iterator;");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bthis\.iterator\b", "this._iterator");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"(?<![A-Za-z0-9_])iterator\.(hasNext|next|remove)\(", "_iterator.$1(");

        // System output, error, exit, and timing methods
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.out\.println\b", "Console.WriteLine");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.out\.print\b", "Console.Write");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.err\.println\b", "Console.Error.WriteLine");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.err\.print\b", "Console.Error.Write");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.exit\b", "Environment.Exit");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.currentTimeMillis\(\)", "DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.nanoTime\(\)", "Stopwatch.GetTimestamp()");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.arraycopy\b", "Array.Copy");

        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.out\b", "Console.Out");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.err\b", "Console.Error");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bSystem\.in\b", "Console.In");

        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bout\b", "@out");

        // in keyword when used as parameter or variable
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"([,\(]\s*[A-Za-z0-9_<>\[\]]+\s+)in\b", "$1@in");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b([A-Za-z0-9_<>\[\]]+\s+)in\s*([;=,])", "$1@in$2");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bin\.", "@in.");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bthis\.in\b", "this.@in");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"([,\(])\s*in\s*([,\)])", "$1@in$2");

        // lock keyword -> @lock (except when followed by '(')
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\block\b(?!\s*\()", "@lock");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bthis\.lock\b", "this.@lock");

        // event, params, fixed, delegate
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bevent\b", "@event");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bparams\b", "@params");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bfixed\b", "@fixed");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bdelegate\b", "@delegate");

        // override keyword when used as parameter or variable
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"([,\(]\s*[A-Za-z0-9_<>\[\]]+\s+)override\b", "$1@override");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\boverride\.", "@override.");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bthis\.override\b", "this.@override");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"([,\(])\s*override\s*([,\)])", "$1@override$2");

        // namespace parameter/variable (not file namespace declaration)
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bnamespace\b(?!(\s+[A-Za-z0-9_.]+;))", "@namespace");

        // 8b. Multi-catch: catch (A | B e) -> catch (Exception e) when (e is A or B)
        // Must run AFTER \bis\b -> @is so that C# 'is' keyword is preserved
        codeWithoutProtectedTokens = TransformMultiCatch(codeWithoutProtectedTokens);

        // 8c. Varargs: Type... name -> params Type[] name
        // Must run AFTER \bparams\b -> @params so that C# 'params' keyword is preserved
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b([A-Za-z0-9_<>\[\]]+)\.\.\.\s*([A-Za-z0-9_@]+)", "params $1[] $2");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b@params\s+([A-Za-z0-9_<>\[\]]+\[\])", "params $1");

        // Switch expressions
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\breturn\s+switch\s*\(", "switch (");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"=\s*switch\s*\(([^)]+)\)\s*\{", "= ($1) switch {");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bcase\s+([^=:\n\r]+?)\s*(?:->|=>)\s*([^;{\n\r]+);", "case $1: return $2;");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bcase\s+([^=:\n\r]+?)\s*(?:->|=>)\s*\{", "case $1: {");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bdefault\s*(?:->|=>)\s*", "default: ");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\byield\s+([^;]+);", "return $1;");

        // 9. Synchronized
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bsynchronized\s*\(", "lock (");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bsynchronized\s+(?!\()", "");

        // 10. Lambdas and method references
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\s->\s", " => ");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"->\s*\{", " => {");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"::", ".");

        // 11. Diamond operator: new Foo<>(...) -> new(...)
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bnew\s+[A-Za-z0-9_.]+\s*<>\s*\(", "new(");

        // 12. Keywords & Types
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bboolean\b", "bool");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bString\b", "string");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bObject\b", "object");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\binstanceof\b", "is");

        // Generics wildcards: <? extends Foo>, <? super Foo>, <?, ?>, <?>
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\?\s+extends\s+([^,>]+)", "$1");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\?\s+super\s+([^,>]+)", "$1");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"(?<=<|,)\s*\?\s*(?=,|>)", "object");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"<\?>", "<object>");

        // Modifiers: static final -> static readonly (never public const)
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bstatic\s+final\b", "static readonly");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bfinal\s+class\b", "sealed class");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bfinal\s+", "");

        // Interface default methods
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bdefault\s+(public|protected|private|internal)\s+", "$1 ");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b(public|protected|private|internal)\s+default\s+", "$1 ");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bdefault\s+(void|bool|byte|sbyte|short|ushort|int|uint|long|ulong|float|double|char|string|[A-Z][A-Za-z0-9_<>]*)\s+", "$1 ");

        // Array parameter/variable syntax: byte b[] -> byte[] b
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b(byte|sbyte|short|ushort|int|uint|long|ulong|float|double|char|bool|string|[A-Z][A-Za-z0-9_]*)\s+([A-Za-z0-9_@]+)\s*\[\s*\]", "$1[] $2");

        // Primitive constants
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bLong\.MAX_VALUE\b", "long.MaxValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bLong\.MIN_VALUE\b", "long.MinValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bInteger\.MAX_VALUE\b", "int.MaxValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bInteger\.MIN_VALUE\b", "int.MinValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bByte\.MAX_VALUE\b", "byte.MaxValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bByte\.MIN_VALUE\b", "byte.MinValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bShort\.MAX_VALUE\b", "short.MaxValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bShort\.MIN_VALUE\b", "short.MinValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bDouble\.MAX_VALUE\b", "double.MaxValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bDouble\.MIN_VALUE\b", "double.MinValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bFloat\.MAX_VALUE\b", "float.MaxValue");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bFloat\.MIN_VALUE\b", "float.MinValue");

        // super(...) in constructor -> : base(...)
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\{\s*super\((.*?)\);", ": base($1)\n    {", RegexOptions.Singleline);
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\{\s*this\((.*?)\);", ": this($1)\n    {", RegexOptions.Singleline);

        // super. -> base.
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bsuper\.", "base.");

        // Type literals: Foo.class -> typeof(Foo)
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b([A-Za-z0-9_<>]+)\.class\b", "typeof($1)");

        // .getClass() -> .GetType()
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\.getClass\(\)", ".GetType()");

        // Array initializers: byte[] bytes = { 0, 1 }; -> byte[] bytes = new byte[] { 0, 1 };
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b(byte|sbyte|short|ushort|int|uint|long|ulong|float|double|char|string)\[\]\s+([A-Za-z0-9_]+)\s*=\s*\{", "$1[] $2 = new $1[] {");

        // Collections mapping
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bArrayList\b", "List");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bHashMap\b", "Dictionary");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bHashtable\b", "Dictionary");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bHashSet\b", "HashSet");

        // assert condition : message; -> Debug.Assert(condition, message);
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bassert\s+([^:]+?)\s*:\s*([^;]+);", "System.Diagnostics.Debug.Assert($1, $2);");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bassert\s+([^;]+);", "System.Diagnostics.Debug.Assert($1);");

        // BigInteger constants and valueOf
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bBigInteger\.ZERO\b", "BigInteger.Zero");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bBigInteger\.ONE\b", "BigInteger.One");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bBigInteger\.TEN\b", "new BigInteger(10)");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bBigInteger\.valueOf\b", "new BigInteger");

        // String.format
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\b[sS]tring\.format\b", "string.Format");

        // bare getClass() -> GetType()
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"(?<!\.)\bgetClass\(\)", "GetType()");

        // raw Comparator -> IComparer<object>
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bComparator\b(?!\s*<)", "IComparer<object>");

        // Array .length property access (not method call like string.length())
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\.length\b(?!\s*\()", ".Length");

        // string keyword when used as parameter or variable name
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bstring\s+string\b", "string @string");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"([,\(]\s*string\s+)string\b", "$1@string");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"\bthis\.string\b", "this.@string");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"([,\(]\s*)string(\s*[,;\)])", "$1@string$2");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"([=+\-*/<>!&|^~]\s*)string(\s*[,;\)])", "$1@string$2");
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens, @"(\breturn\s+)string(\s*;)", "$1@string$2");

        // Bridge object methods: equals, hashCode, toString
        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens,
            @"(?:/\*\s*@Override\s*\*/\s*)?public\s+(?:override\s+|virtual\s+)?bool\s+equals\s*\(\s*object\s+([A-Za-z0-9_]+)\s*\)\s*\{",
            "public override bool Equals(object? $1) => equals($1);\n    /* @Override */\n    public bool equals(object $1) {");

        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens,
            @"(?:/\*\s*@Override\s*\*/\s*)?public\s+(?:override\s+|virtual\s+)?int\s+hashCode\s*\(\s*\)\s*\{",
            "public override int GetHashCode() => hashCode();\n    /* @Override */\n    public int hashCode() {");

        codeWithoutProtectedTokens = Regex.Replace(codeWithoutProtectedTokens,
            @"(?:/\*\s*@Override\s*\*/\s*)?public\s+(?:override\s+|virtual\s+)?string\s+toString\s*\(\s*\)\s*\{",
            "public override string ToString() => toString();\n    /* @Override */\n    public string toString() {");

        // 13. Restore protected comments and string literals
        string restored = RestoreProtectedTokens(codeWithoutProtectedTokens, protectedTokens);

        // Prepend common C# usings and type aliases at top
        var sb = new StringBuilder();
        sb.AppendLine("// <auto-generated> Transpiled from Java source by GhidraNet Transpiler </auto-generated>");
        sb.AppendLine("using System;");
        sb.AppendLine("using System.Collections;");
        sb.AppendLine("using System.Collections.Generic;");
        sb.AppendLine("using System.IO;");
        sb.AppendLine("using System.Linq;");
        sb.AppendLine("using System.Numerics;");
        sb.AppendLine("using System.Text;");
        sb.AppendLine("using ghidra.util.datastruct;");
        sb.AppendLine("using Long = ghidra.util.datastruct.JavaLong;");
        sb.AppendLine("using Integer = ghidra.util.datastruct.JavaInteger;");
        sb.AppendLine("using Short = ghidra.util.datastruct.JavaShort;");
        sb.AppendLine("using Byte = ghidra.util.datastruct.JavaByte;");
        sb.AppendLine("using Double = ghidra.util.datastruct.JavaDouble;");
        sb.AppendLine("using Float = ghidra.util.datastruct.JavaFloat;");
        sb.AppendLine("using Boolean = ghidra.util.datastruct.JavaBoolean;");
        sb.AppendLine("using Character = ghidra.util.datastruct.JavaCharacter;");
        sb.AppendLine("using Math = ghidra.util.datastruct.JavaMath;");
        sb.AppendLine("using File = ghidra.util.datastruct.JavaFile;");
        sb.AppendLine("using Pattern = ghidra.util.datastruct.JavaPattern;");
        sb.AppendLine("using Matcher = ghidra.util.datastruct.JavaMatcher;");
        sb.AppendLine("using Throwable = System.Exception;");
        sb.AppendLine("using Runnable = System.Action;");
        sb.AppendLine();
        sb.Append(restored);

        return sb.ToString();
    }

    private static string TransformTryWithResources(string code)
    {
        var sb = new StringBuilder();
        int i = 0;
        int n = code.Length;

        while (i < n)
        {
            int tryIdx = code.IndexOf("try", i, StringComparison.Ordinal);
            if (tryIdx == -1)
            {
                sb.Append(code[i..]);
                break;
            }

            bool isStartWord = tryIdx == 0 || !char.IsLetterOrDigit(code[tryIdx - 1]) && code[tryIdx - 1] != '_';
            int afterTry = tryIdx + 3;
            bool isEndWord = afterTry >= n || !char.IsLetterOrDigit(code[afterTry]) && code[afterTry] != '_';

            if (!isStartWord || !isEndWord)
            {
                sb.Append(code.AsSpan(i, tryIdx - i + 3));
                i = tryIdx + 3;
                continue;
            }

            int p = afterTry;
            while (p < n && char.IsWhiteSpace(code[p])) p++;

            if (p < n && code[p] == '(')
            {
                int openParen = p;
                int depth = 1;
                p++;
                while (p < n && depth > 0)
                {
                    if (code[p] == '(') depth++;
                    else if (code[p] == ')') depth--;
                    p++;
                }

                if (depth == 0)
                {
                    int closeParen = p - 1;
                    string resources = code.Substring(openParen + 1, closeParen - openParen - 1).Trim();

                    int afterParen = closeParen + 1;
                    while (afterParen < n && char.IsWhiteSpace(code[afterParen])) afterParen++;

                    if (afterParen < n && code[afterParen] == '{')
                    {
                        int openBrace = afterParen;
                        int bDepth = 1;
                        int b = openBrace + 1;
                        while (b < n && bDepth > 0)
                        {
                            if (code[b] == '{') bDepth++;
                            else if (code[b] == '}') bDepth--;
                            b++;
                        }

                        if (bDepth == 0)
                        {
                            int closeBrace = b - 1;
                            string blockBody = code.Substring(openBrace + 1, closeBrace - openBrace - 1);

                            int afterBrace = closeBrace + 1;
                            while (afterBrace < n && char.IsWhiteSpace(code[afterBrace])) afterBrace++;

                            bool hasCatchOrFinally = false;
                            if (afterBrace + 5 <= n && code.Substring(afterBrace, 5) == "catch")
                            {
                                hasCatchOrFinally = true;
                            }
                            else if (afterBrace + 7 <= n && code.Substring(afterBrace, 7) == "finally")
                            {
                                hasCatchOrFinally = true;
                            }

                            sb.Append(code[i..tryIdx]);

                            var resParts = resources.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                            
                            if (hasCatchOrFinally)
                            {
                                sb.AppendLine("try");
                                sb.AppendLine("{");
                                foreach (var res in resParts)
                                {
                                    sb.AppendLine($"    using ({res})");
                                }
                                sb.AppendLine("    {");
                                sb.Append(blockBody);
                                sb.AppendLine();
                                sb.AppendLine("    }");
                                sb.Append("}");
                            }
                            else
                            {
                                for (int r = 0; r < resParts.Length; r++)
                                {
                                    sb.AppendLine($"using ({resParts[r]})");
                                }
                                sb.Append("{");
                                sb.Append(blockBody);
                                sb.Append("}");
                            }

                            i = closeBrace + 1;
                            continue;
                        }
                    }
                }
            }

            sb.Append(code.AsSpan(i, tryIdx - i + 3));
            i = tryIdx + 3;
        }

        return sb.ToString();
    }

    private static string TransformEnhancedForLoops(string code)
    {
        var sb = new StringBuilder();
        int i = 0;
        int n = code.Length;

        while (i < n)
        {
            int forIdx = code.IndexOf("for", i, StringComparison.Ordinal);
            if (forIdx == -1)
            {
                sb.Append(code[i..]);
                break;
            }

            bool isStartWord = forIdx == 0 || !char.IsLetterOrDigit(code[forIdx - 1]) && code[forIdx - 1] != '_';
            int afterFor = forIdx + 3;
            bool isEndWord = afterFor >= n || !char.IsLetterOrDigit(code[afterFor]) && code[afterFor] != '_';

            if (!isStartWord || !isEndWord)
            {
                sb.Append(code.AsSpan(i, forIdx - i + 3));
                i = forIdx + 3;
                continue;
            }

            int p = afterFor;
            while (p < n && char.IsWhiteSpace(code[p])) p++;

            if (p < n && code[p] == '(')
            {
                int openParen = p;
                int depth = 1;
                p++;
                int colonIdx = -1;
                bool hasSemicolon = false;
                int angleDepth = 0;
                int bracketDepth = 0;

                while (p < n && depth > 0)
                {
                    char ch = code[p];
                    if (ch == '(') depth++;
                    else if (ch == ')') depth--;
                    else if (depth == 1)
                    {
                        if (ch == '<') angleDepth++;
                        else if (ch == '>') angleDepth--;
                        else if (ch == '[') bracketDepth++;
                        else if (ch == ']') bracketDepth--;
                        else if (ch == ';') hasSemicolon = true;
                        else if (ch == ':' && angleDepth == 0 && bracketDepth == 0 && colonIdx == -1)
                        {
                            colonIdx = p;
                        }
                    }
                    p++;
                }

                if (depth == 0 && !hasSemicolon && colonIdx != -1)
                {
                    int closeParen = p - 1;
                    string varDecl = code.Substring(openParen + 1, colonIdx - openParen - 1).Trim();
                    string collection = code.Substring(colonIdx + 1, closeParen - colonIdx - 1).Trim();

                    if (varDecl.StartsWith("final "))
                    {
                        varDecl = varDecl.Substring(6).TrimStart();
                    }

                    sb.Append(code[i..forIdx]);
                    sb.Append($"foreach ({varDecl} in {collection})");
                    i = closeParen + 1;
                    continue;
                }
            }

            sb.Append(code.AsSpan(i, forIdx - i + 3));
            i = forIdx + 3;
        }

        return sb.ToString();
    }

    private static string TransformTypeDeclarations(string code)
    {
        var pattern = new Regex(@"\b(public|protected|private|internal|abstract|sealed|static|\s)*\b(class|record|interface)\s+([A-Za-z0-9_]+)", RegexOptions.Compiled);
        var sb = new StringBuilder();
        int lastIdx = 0;

        foreach (Match m in pattern.Matches(code))
        {
            int headerStart = m.Index;
            if (headerStart < lastIdx)
            {
                continue;
            }

            int nameEnd = m.Index + m.Length;
            string kind = m.Groups[2].Value;
            string name = m.Groups[3].Value;

            int p = nameEnd;
            string typeParamsClause = "";
            var constraints = new List<string>();

            if (p < code.Length && code[p] == '<')
            {
                int angleDepth = 1;
                int angleStart = p;
                p++;
                while (p < code.Length && angleDepth > 0)
                {
                    if (code[p] == '<') angleDepth++;
                    else if (code[p] == '>') angleDepth--;
                    p++;
                }

                if (angleDepth == 0)
                {
                    string rawParams = code.Substring(angleStart + 1, p - angleStart - 2);
                    var parsedParams = new List<string>();
                    var parts = SplitGenericParams(rawParams);
                    foreach (var part in parts)
                    {
                        int extendsIdx = part.IndexOf(" extends ", StringComparison.Ordinal);
                        if (extendsIdx >= 0)
                        {
                            string paramName = part.Substring(0, extendsIdx).Trim();
                            string bound = part.Substring(extendsIdx + 9).Trim().Replace('&', ',');
                            parsedParams.Add(paramName);
                            constraints.Add($"where {paramName} : {bound}");
                        }
                        else
                        {
                            parsedParams.Add(part.Trim());
                        }
                    }
                    typeParamsClause = "<" + string.Join(", ", parsedParams) + ">";
                }
            }

            // Capture record primary constructor parameters if present: record Foo(...)
            string recordParams = "";
            int tempP = p;
            while (tempP < code.Length && char.IsWhiteSpace(code[tempP])) tempP++;
            if (tempP < code.Length && code[tempP] == '(')
            {
                int parenDepth = 1;
                int parenStart = tempP;
                tempP++;
                while (tempP < code.Length && parenDepth > 0)
                {
                    if (code[tempP] == '(') parenDepth++;
                    else if (code[tempP] == ')') parenDepth--;
                    tempP++;
                }
                if (parenDepth == 0)
                {
                    recordParams = code.Substring(parenStart, tempP - parenStart);
                    p = tempP;
                }
            }

            int braceIdx = code.IndexOf('{', p);
            if (braceIdx == -1 || braceIdx - p > 2000) continue;

            int semiIdx = code.IndexOf(';', p);
            if (semiIdx != -1 && semiIdx < braceIdx) continue;

            string rest = code.Substring(p, braceIdx - p).Trim();

            string extendsType = "";
            string implementsTypes = "";

            int extIdx = IndexOfWord(rest, "extends");
            int impIdx = IndexOfWord(rest, "implements");

            if (extIdx >= 0)
            {
                if (impIdx > extIdx)
                {
                    extendsType = rest.Substring(extIdx + 7, impIdx - (extIdx + 7)).Trim();
                    implementsTypes = rest.Substring(impIdx + 10).Trim();
                }
                else
                {
                    extendsType = rest.Substring(extIdx + 7).Trim();
                }
            }
            else if (impIdx >= 0)
            {
                implementsTypes = rest.Substring(impIdx + 10).Trim();
            }

            var baseList = new List<string>();
            if (!string.IsNullOrEmpty(extendsType)) baseList.Add(extendsType);
            if (!string.IsNullOrEmpty(implementsTypes)) baseList.Add(implementsTypes);

            string baseClause = baseList.Count > 0 ? " : " + string.Join(", ", baseList) : "";
            string whereClause = constraints.Count > 0 ? " " + string.Join(" ", constraints) : "";

            sb.Append(code[lastIdx..headerStart]);
            string prefix = m.Value.Substring(0, m.Value.Length - name.Length);
            sb.Append($"{prefix}{name}{typeParamsClause}{recordParams}{baseClause}{whereClause} ");

            lastIdx = braceIdx;
        }

        sb.Append(code[lastIdx..]);
        return sb.ToString();
    }

    private static int IndexOfWord(string s, string word)
    {
        int idx = 0;
        while ((idx = s.IndexOf(word, idx, StringComparison.Ordinal)) >= 0)
        {
            bool startOk = idx == 0 || !char.IsLetterOrDigit(s[idx - 1]) && s[idx - 1] != '_';
            int end = idx + word.Length;
            bool endOk = end >= s.Length || !char.IsLetterOrDigit(s[end]) && s[end] != '_';
            if (startOk && endOk) return idx;
            idx += word.Length;
        }
        return -1;
    }

    private static List<string> SplitGenericParams(string s)
    {
        var list = new List<string>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '<') depth++;
            else if (s[i] == '>') depth--;
            else if (s[i] == ',' && depth == 0)
            {
                list.Add(s.Substring(start, i - start));
                start = i + 1;
            }
        }
        if (start < s.Length) list.Add(s.Substring(start));
        return list;
    }

    private static string TransformRichEnums(string code)
    {
        var enumRegex = new Regex(@"\b(public|protected|private|internal|\s)*\benum\s+([A-Za-z0-9_]+)(\s+implements\s+[^{]+)?\s*\{", RegexOptions.Compiled);
        var sb = new StringBuilder();
        int lastIdx = 0;

        foreach (Match m in enumRegex.Matches(code))
        {
            int headerStart = m.Index;
            if (headerStart < lastIdx) continue;

            string name = m.Groups[2].Value;
            string implementsClause = m.Groups[3].Value.Trim();
            int openBrace = m.Index + m.Length - 1;

            int depth = 1;
            int p = openBrace + 1;
            int semiIdx = -1;

            while (p < code.Length && depth > 0)
            {
                if (code[p] == '{') depth++;
                else if (code[p] == '}') depth--;
                else if (depth == 1 && code[p] == ';' && semiIdx == -1)
                {
                    semiIdx = p;
                }
                p++;
            }

            if (depth != 0) continue;
            int closeBrace = p - 1;

            bool hasImplements = !string.IsNullOrEmpty(implementsClause);
            bool hasSemi = semiIdx != -1;

            if (!hasImplements && !hasSemi)
            {
                continue;
            }

            string prefix = m.Value.Substring(0, m.Value.IndexOf("enum", StringComparison.Ordinal));
            string baseClause = hasImplements ? " : " + implementsClause.Substring(10).Trim() : "";

            sb.Append(code[lastIdx..headerStart]);
            sb.Append($"{prefix}class {name}{baseClause}\n{{");

            string enumConstantsPart;
            string remainderPart = "";

            if (hasSemi)
            {
                enumConstantsPart = code.Substring(openBrace + 1, semiIdx - openBrace - 1);
                remainderPart = code.Substring(semiIdx + 1, closeBrace - semiIdx - 1);
            }
            else
            {
                enumConstantsPart = code.Substring(openBrace + 1, closeBrace - openBrace - 1);
            }

            var constants = SplitEnumConstants(enumConstantsPart);
            foreach (var c in constants)
            {
                if (string.IsNullOrWhiteSpace(c)) continue;
                string cleaned = TokenRegex.Replace(c, "").Trim();
                var mIdent = Regex.Match(cleaned, @"\b([A-Za-z][A-Za-z0-9_]*)\b(?:\s*\((.*?)\))?", RegexOptions.Singleline);
                if (!mIdent.Success) continue;
                string constName = mIdent.Groups[1].Value;
                string args = mIdent.Groups[2].Success ? $"({mIdent.Groups[2].Value})" : "()";
                sb.AppendLine($"\tpublic static readonly {name} {constName} = new{args};");
            }

            sb.Append(remainderPart);
            sb.Append("}");

            lastIdx = closeBrace + 1;
        }

        sb.Append(code[lastIdx..]);
        return sb.ToString();
    }

    private static List<string> SplitEnumConstants(string s)
    {
        var list = new List<string>();
        int parenDepth = 0;
        int braceDepth = 0;
        int start = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '(') parenDepth++;
            else if (s[i] == ')') parenDepth--;
            else if (s[i] == '{') braceDepth++;
            else if (s[i] == '}') braceDepth--;
            else if (s[i] == ',' && parenDepth == 0 && braceDepth == 0)
            {
                list.Add(s.Substring(start, i - start).Trim());
                start = i + 1;
            }
        }
        if (start < s.Length) list.Add(s.Substring(start).Trim());
        return list;
    }

    private static string TransformAnonymousClasses(string code)
    {
        var anonRegex = new Regex(@"\bnew\s+([A-Za-z0-9_<>.]+)\s*\(([^)]*)\)\s*\{", RegexOptions.Compiled);
        var sb = new StringBuilder();
        var anonClasses = new List<string>();
        int lastIdx = 0;
        int anonCount = 0;

        foreach (Match m in anonRegex.Matches(code))
        {
            int headerStart = m.Index;
            if (headerStart < lastIdx) continue;

            string baseType = m.Groups[1].Value.Trim();
            string args = m.Groups[2].Value.Trim();
            int openBrace = m.Index + m.Length - 1;

            int depth = 1;
            int p = openBrace + 1;
            while (p < code.Length && depth > 0)
            {
                if (code[p] == '{') depth++;
                else if (code[p] == '}') depth--;
                p++;
            }

            if (depth != 0) continue;
            int closeBrace = p - 1;

            string body = code.Substring(openBrace + 1, closeBrace - openBrace - 1);

            // Must contain method-like parentheses and braces to be an anonymous class
            if (!body.Contains('(') || !body.Contains('{'))
            {
                continue;
            }

            anonCount++;
            string safeTypeName = Regex.Replace(baseType, @"[<>,.]", "_").Trim('_');
            string anonClassName = $"_Anon_{safeTypeName}_{anonCount}";

            sb.Append(code[lastIdx..headerStart]);
            sb.Append($"new {anonClassName}({args})");

            var classSb = new StringBuilder();
            classSb.AppendLine();
            classSb.AppendLine($"\tinternal class {anonClassName} : {baseType}");
            classSb.AppendLine("\t{");
            if (!string.IsNullOrEmpty(args))
            {
                classSb.AppendLine($"\t\tpublic {anonClassName}() : base({args}) {{}}");
            }
            classSb.Append(body);
            classSb.AppendLine();
            classSb.AppendLine("\t}");
            anonClasses.Add(classSb.ToString());

            lastIdx = closeBrace + 1;
        }

        sb.Append(code[lastIdx..]);

        if (anonClasses.Count > 0)
        {
            string fullCode = sb.ToString();
            int lastBrace = fullCode.LastIndexOf('}');
            if (lastBrace != -1)
            {
                var combined = new StringBuilder();
                combined.Append(fullCode.Substring(0, lastBrace));
                foreach (var ac in anonClasses)
                {
                    combined.AppendLine(ac);
                }
                combined.Append(fullCode.Substring(lastBrace));
                return combined.ToString();
            }
            else
            {
                foreach (var ac in anonClasses)
                {
                    sb.AppendLine(ac);
                }
                return sb.ToString();
            }
        }

        return sb.ToString();
    }

    private static string TransformMultiCatch(string code)
    {
        var regex = new Regex(@"\bcatch\s*\(\s*([A-Za-z0-9_.]+(?:\s*\|\s*[A-Za-z0-9_.]+)+)\s+([A-Za-z0-9_@]+)\s*\)", RegexOptions.Compiled);
        return regex.Replace(code, m =>
        {
            string types = m.Groups[1].Value;
            string varName = m.Groups[2].Value;
            var parts = types.Split('|', StringSplitOptions.TrimEntries);
            string cond = string.Join(" or ", parts);
            return $"catch (Exception {varName}) when ({varName} is {cond})";
        });
    }

    private static string TransformGenericMethods(string code)
    {
        var regex = new Regex(@"\b((?:public|protected|private|internal|static|final|synchronized|\s)+)<([A-Za-z0-9_,\s<>&]+)>\s+([A-Za-z0-9_<>,\s\[\]\.\?]+?)\s+([A-Za-z0-9_]+)\s*\(", RegexOptions.Compiled);
        return regex.Replace(code, m =>
        {
            string rawMods = m.Groups[1].Value.Replace("final", "");
            string leadingWs = "";
            int wsIdx = 0;
            while (wsIdx < rawMods.Length && char.IsWhiteSpace(rawMods[wsIdx])) leadingWs += rawMods[wsIdx++];
            string modifiers = rawMods.Substring(wsIdx).Trim();
            string rawParams = m.Groups[2].Value.Trim();
            string returnType = m.Groups[3].Value.Trim();
            string methodName = m.Groups[4].Value.Trim();

            var parsedParams = new List<string>();
            var constraints = new List<string>();
            var parts = SplitGenericParams(rawParams);
            foreach (var part in parts)
            {
                int extendsIdx = part.IndexOf(" extends ", StringComparison.Ordinal);
                if (extendsIdx >= 0)
                {
                    string paramName = part.Substring(0, extendsIdx).Trim();
                    string bound = part.Substring(extendsIdx + 9).Trim().Replace('&', ',');
                    parsedParams.Add(paramName);
                    constraints.Add($"where {paramName} : {bound}");
                }
                else
                {
                    parsedParams.Add(part.Trim());
                }
            }

            string cleanParams = "<" + string.Join(", ", parsedParams) + ">";
            if (constraints.Count > 0)
            {
                return $"{leadingWs}{modifiers} {returnType} {methodName}{cleanParams}/* {string.Join(" ", constraints)} */(";
            }
            return $"{leadingWs}{modifiers} {returnType} {methodName}{cleanParams}(";
        });
    }

    private static (string CodeWithoutProtectedTokens, List<string> ProtectedTokens) ExtractProtectedTokens(string code)
    {
        var tokens = new List<string>();
        var sb = new StringBuilder();
        int n = code.Length;
        int i = 0;

        while (i < n)
        {
            char c = code[i];

            // 1. Line Comment: // ...
            if (c == '/' && i + 1 < n && code[i + 1] == '/')
            {
                int start = i;
                i += 2;
                while (i < n && code[i] != '\n' && code[i] != '\r')
                {
                    i++;
                }
                string comment = code[start..i];
                tokens.Add(comment);
                sb.Append($"__PROT_TOKEN_{tokens.Count - 1}__");
            }
            // 2. Block Comment: /* ... */
            else if (c == '/' && i + 1 < n && code[i + 1] == '*')
            {
                int start = i;
                i += 2;
                while (i + 1 < n && !(code[i] == '*' && code[i + 1] == '/'))
                {
                    i++;
                }
                if (i + 1 < n) i += 2; else i = n;
                string comment = code[start..i];
                tokens.Add(comment);
                sb.Append($"__PROT_TOKEN_{tokens.Count - 1}__");
            }
            // 3. String Literal: " ... "
            else if (c == '"')
            {
                int start = i++;
                while (i < n)
                {
                    if (code[i] == '\\' && i + 1 < n)
                    {
                        i += 2;
                    }
                    else if (code[i] == '"')
                    {
                        i++;
                        break;
                    }
                    else
                    {
                        i++;
                    }
                }
                string str = code[start..i];
                tokens.Add(str);
                sb.Append($"__PROT_TOKEN_{tokens.Count - 1}__");
            }
            // 4. Character Literal: ' ... '
            else if (c == '\'')
            {
                int start = i++;
                while (i < n)
                {
                    if (code[i] == '\\' && i + 1 < n)
                    {
                        i += 2;
                    }
                    else if (code[i] == '\'')
                    {
                        i++;
                        break;
                    }
                    else
                    {
                        i++;
                    }
                }
                string ch = code[start..i];
                tokens.Add(ch);
                sb.Append($"__PROT_TOKEN_{tokens.Count - 1}__");
            }
            else
            {
                sb.Append(c);
                i++;
            }
        }

        return (sb.ToString(), tokens);
    }

    private static string RestoreProtectedTokens(string code, List<string> tokens)
    {
        return TokenRegex.Replace(code, m =>
        {
            if (int.TryParse(m.Groups[1].Value, out int idx) && idx >= 0 && idx < tokens.Count)
            {
                return tokens[idx];
            }
            return m.Value;
        });
    }
}
