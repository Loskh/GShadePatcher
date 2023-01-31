using System.Runtime.InteropServices;
using GShadePatcher;
using Iced.Intel;
using System.Reflection;
using System.Linq.Expressions;
using System.Diagnostics;
using Microsoft.Win32;
using System;

namespace GShadePatcher {
    internal class Program {

        //const string SkipUpdateSig = "74 ?? 48 8D 8F ?? ?? ?? ?? E8 ?? ?? ?? ?? 88 87";
        const string SkipUpdateSig = "74 ?? 48 8B 15 ?? ?? ?? ?? 48 8D 4F";
        [STAThread]
        static void Main(string[] args) {
            Console.WriteLine($"补丁版本: {Assembly.GetExecutingAssembly().GetName().Version}");
            try {
                var gamePath = TryGamePaths();
                var ofd = new OpenFileDialog();
                if (gamePath != null) {
                    ofd.InitialDirectory = gamePath;
                }
                ofd.Multiselect = false;
                ofd.CheckFileExists = true;
                ofd.Title = "选择要进行Patch的GShade64";
                ofd.Filter = "GShade64 dll file|*.dll";
                var gshadeDllPath = string.Empty;
                if (ofd.ShowDialog() == DialogResult.OK) {
                    gshadeDllPath = ofd.FileName;
                }
                else {
                    throw new Exception("请选择GShade64.dll或者ffxiv_dx11.exe所在文件夹下的dxgi.dll或者d3d11.dll");
                }
                gshadeDllPath = gshadeDllPath.Trim();
                Console.WriteLine($"选择DLL路径:{gshadeDllPath}");
                if (File.ResolveLinkTarget(gshadeDllPath, true) != null) {
                    gshadeDllPath = File.ResolveLinkTarget(gshadeDllPath, true).FullName;
                }
                var gshadeDllVersion = FileVersionInfo.GetVersionInfo(gshadeDllPath);
                Console.WriteLine(gshadeDllVersion);
                var file = File.ReadAllBytes(gshadeDllPath);
                var module = Marshal.AllocHGlobal(file.Length);
                Marshal.Copy(file, 0, module, file.Length);
                var scanner = new SigScanner(module);
                Console.WriteLine($"Current Sig: {SkipUpdateSig}");
                if (scanner.TryScanText(SkipUpdateSig, out var ptr)) {
                    var offset = (int)((long)ptr - (long)scanner.SearchBase);
                    Console.WriteLine($"Find: 0x{offset:X8}");

                    var disasmNum = 32;
                    var bytes = new byte[disasmNum];
                    Console.WriteLine("Patch前:");
                    Marshal.Copy(module + offset, bytes, 0, disasmNum);
                    Disassemble(bytes, 0x180000C00 + (ulong)offset);

                    Marshal.WriteByte(ptr, 0xEB);

                    Console.WriteLine();
                    Console.WriteLine("Patch后:");
                    Marshal.Copy(module + offset, bytes, 0, disasmNum);
                    Disassemble(bytes, 0x180000C00 + (ulong)offset);

                    Console.WriteLine();

                    File.Copy(gshadeDllPath, $"{gshadeDllPath}.bak", true);
                    File.Delete(gshadeDllPath);
                    Marshal.Copy(module, file, 0, file.Length);
                    File.WriteAllBytes(gshadeDllPath, file);
                    Console.WriteLine("Patch成功");
                }
                else {
                    throw new Exception("Can't find any referenced address!");
                }
            }
            catch (UnauthorizedAccessException ex) {
                Console.WriteLine();
                Console.WriteLine(ex.Message);
                Console.WriteLine("无权写入，请尝试退出程序后右键管理员运行。");
            }
            catch (Exception ex) {
                Console.WriteLine();
                Console.WriteLine($"{ex.GetType().FullName}:{ex.Message}");
                Console.WriteLine("反馈地址: https://nga.178.com/read.php?tid=26796541");
                Console.WriteLine("请带上日志或者截图,反馈前请尝试原贴中最新版是否可用。");
            }

            Console.WriteLine("按任意键继续...");
            Console.ReadKey();
        }

        public static string? TryGamePaths() {
            foreach (var registryView in new RegistryView[] { RegistryView.Registry32, RegistryView.Registry64 }) {
                using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView)) {
                    using (var subkey = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{2B41E132-07DF-4925-A3D3-F2D1765CCDFE}")) {
                        if (subkey != null && subkey.GetValue("DisplayIcon", null) is string path) {
                            // DisplayIcon includes "boot\ffxivboot.exe", need to remove it
                            path = Directory.GetParent(path).FullName;
                            if (Directory.Exists(path)) {
                                return path;
                            }
                        }
                    }
                    using (var subkey = hklm.OpenSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\最终幻想14")) {
                        if (subkey != null && subkey.GetValue("InstallLocation", null) is string path) {
                            if (Directory.Exists(path)) {
                                return path;
                            }
                        }
                    }
                }
            }
            return null;
        }
        public static void Disassemble(byte[] codeBytes, ulong address) {
            var codeReader = new ByteArrayCodeReader(codeBytes);
            var decoder = Decoder.Create(64, codeReader);
            decoder.IP = address;

            var formatter = new MasmFormatter();
            var output = new FormatterOutputImpl();
            foreach (var instr in decoder) {
                output.List.Clear();
                formatter.Format(instr, output);
                Console.Write(instr.IP.ToString("X16"));
                Console.Write(" ");
                Console.Write($"{BitConverter.ToString(codeBytes[(int)(instr.IP - address)..(int)(instr.IP - address + (ulong)instr.Length)]).Replace('-', ' '),-34}");
                foreach (var (text, kind) in output.List) {
                    Console.ForegroundColor = GetColor(kind);
                    Console.Write(text);
                }
                Console.WriteLine();
                Console.ResetColor();
            }
        }

        sealed class FormatterOutputImpl : FormatterOutput {
            public readonly List<(string text, FormatterTextKind kind)> List =
                new List<(string text, FormatterTextKind kind)>();
            public override void Write(string text, FormatterTextKind kind) => List.Add((text, kind));
        }

        static ConsoleColor GetColor(FormatterTextKind kind) {
            switch (kind) {
                case FormatterTextKind.Directive:
                case FormatterTextKind.Keyword:
                    return ConsoleColor.Yellow;

                case FormatterTextKind.Prefix:
                case FormatterTextKind.Mnemonic:
                    return ConsoleColor.Red;

                case FormatterTextKind.Register:
                    return ConsoleColor.Magenta;

                case FormatterTextKind.Number:
                    return ConsoleColor.Green;

                default:
                    return ConsoleColor.White;
            }
        }
    }
}