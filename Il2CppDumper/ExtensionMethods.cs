using BepInEx.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace Il2CppDumper
{
    /// <summary>
    /// Provides extension methods for logging and processing IL2CPP files.
    /// </summary>
    public class ExtensionMethods
    {
        /// <summary>
        /// The logger instance for the Il2CppDumper extension methods.
        /// </summary>
        public static ManualLogSource logger;

        static ExtensionMethods()
        {
            logger = new ManualLogSource("Il2CppDumper");
            Logger.Sources.Add(logger);
        }

        /// <summary>
        /// Initializes the IL2CPP metadata and IL2CPP file.
        /// </summary>
        /// <param name="il2cppBytes">The IL2CPP file bytes.</param>
        /// <param name="metadataBytes">The metadata file bytes.</param>
        /// <param name="metadata">The initialized metadata object.</param>
        /// <param name="il2Cpp">The initialized IL2CPP object.</param>
        /// <returns><c>true</c> if initialization is successful; otherwise, <c>false</c>.</returns>
        public static bool Init(byte[] il2cppBytes, byte[] metadataBytes, out Metadata metadata, out Il2Cpp il2Cpp)
        {
            ExtensionMethods.logger.LogInfo("Initializing metadata...");
            //var metadataBytes = File.ReadAllBytes(metadataPath);
            metadata = new Metadata(new MemoryStream(metadataBytes));
            ExtensionMethods.logger.LogInfo($"Metadata Version: {metadata.Version}");

            ExtensionMethods.logger.LogInfo("Initializing il2cpp file...");
            //var il2cppBytes = File.ReadAllBytes(il2cppPath);
            var il2cppMagic = BitConverter.ToUInt32(il2cppBytes, 0);
            var il2CppMemory = new MemoryStream(il2cppBytes);
            switch (il2cppMagic)
            {
                default:
                    throw new NotSupportedException("ERROR: il2cpp file not supported.");
                case 0x6D736100:
                    var web = new WebAssembly(il2CppMemory);
                    il2Cpp = web.CreateMemory();
                    break;
                case 0x304F534E:
                    var nso = new NSO(il2CppMemory);
                    il2Cpp = nso.UnCompress();
                    break;
                case 0x905A4D: //PE
                    il2Cpp = new PE(il2CppMemory);
                    break;
                case 0x464c457f: //ELF
                    if (il2cppBytes[4] == 2) //ELF64
                    {
                        il2Cpp = new Elf64(il2CppMemory);
                    }
                    else
                    {
                        il2Cpp = new Elf(il2CppMemory);
                    }
                    break;
                case 0xCAFEBABE: //FAT Mach-O
                case 0xBEBAFECA:
                    var machofat = new MachoFat(new MemoryStream(il2cppBytes));
                    ExtensionMethods.logger.LogInfo("Select Platform: ");
                    for (var i = 0; i < machofat.fats.Length; i++)
                    {
                        var fat = machofat.fats[i];
                        ExtensionMethods.logger.LogInfo(fat.magic == 0xFEEDFACF ? $"{i + 1}.64bit " : $"{i + 1}.32bit ");
                    }
                    ExtensionMethods.logger.LogInfo($"\n");
                    var key = Console.ReadKey(true);
                    var index = int.Parse(key.KeyChar.ToString()) - 1;
                    var magic = machofat.fats[index % 2].magic;
                    il2cppBytes = machofat.GetMacho(index % 2);
                    il2CppMemory = new MemoryStream(il2cppBytes);
                    if (magic == 0xFEEDFACF)
                        goto case 0xFEEDFACF;
                    else
                        goto case 0xFEEDFACE;
                case 0xFEEDFACF: // 64bit Mach-O
                    il2Cpp = new Macho64(il2CppMemory);
                    break;
                case 0xFEEDFACE: // 32bit Mach-O
                    il2Cpp = new Macho(il2CppMemory);
                    break;
            }
            var version = metadata.Version;
            il2Cpp.SetProperties(version, metadata.metadataUsagesCount);
            ExtensionMethods.logger.LogInfo($"Il2Cpp Version: {il2Cpp.Version}");
            if (false || il2Cpp.CheckDump())
            {
                if (il2Cpp is ElfBase elf)
                {
                    ExtensionMethods.logger.LogInfo("Detected this may be a dump file.");
                    ExtensionMethods.logger.LogInfo("Input il2cpp dump address or input 0 to force continue:");
                    var DumpAddr = Convert.ToUInt64(Console.ReadLine(), 16);
                    if (DumpAddr != 0)
                    {
                        il2Cpp.ImageBase = DumpAddr;
                        il2Cpp.IsDumped = true;
                        if (!false)
                        {
                            elf.Reload();
                        }
                    }
                }
                else
                {
                    il2Cpp.IsDumped = true;
                }
            }

            ExtensionMethods.logger.LogInfo("Searching...");
            try
            {
                var flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length);
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    if (!flag && il2Cpp is PE)
                    {
                        ExtensionMethods.logger.LogInfo("Use custom PE loader");
                        /*il2Cpp = PELoader.Load(il2cppBytes);
                        il2Cpp.SetProperties(version, metadata.metadataUsagesCount);
                        flag = il2Cpp.PlusSearch(metadata.methodDefs.Count(x => x.methodIndex >= 0), metadata.typeDefs.Length, metadata.imageDefs.Length);*/
                        throw new NotImplementedException("Doubt this case will be triggered.");
                    }
                }
                if (!flag)
                {
                    flag = il2Cpp.Search();
                }
                if (!flag)
                {
                    flag = il2Cpp.SymbolSearch();
                }
                if (!flag)
                {
                    ExtensionMethods.logger.LogError("Can't use auto mode to process file, try manual mode.");
                    ExtensionMethods.logger.LogInfo("Input CodeRegistration: ");
                    var codeRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    ExtensionMethods.logger.LogInfo("Input MetadataRegistration: ");
                    var metadataRegistration = Convert.ToUInt64(Console.ReadLine(), 16);
                    il2Cpp.Init(codeRegistration, metadataRegistration);
                }
                if (il2Cpp.Version >= 27 && il2Cpp.IsDumped)
                {
                    var typeDef = metadata.typeDefs[0];
                    var il2CppType = il2Cpp.types[typeDef.byvalTypeIndex];
                    metadata.ImageBase = il2CppType.data.typeHandle - metadata.header.typeDefinitionsOffset;
                }
            }
            catch (Exception e)
            {
                logger.LogError(e);
                logger.LogError("ERROR: An error occurred while processing.");
                return false;
            }
            return true;
        }

        /// <summary>
        /// Generates Cecil assemblies from the metadata and IL2CPP.
        /// </summary>
        /// <param name="metadata">The metadata object.</param>
        /// <param name="il2Cpp">The IL2CPP object.</param>
        /// <param name="Assemblies">The generated AssemblyDefinitions.</param>
        public static void GenerateCecilAssemblies(Metadata metadata, Il2Cpp il2Cpp, out List<Mono.Cecil.AssemblyDefinition> Assemblies)
        {
            ExtensionMethods.logger.LogInfo("Generating AssemblyDefinition...");
            var executor = new Il2CppExecutor(metadata, il2Cpp);
            var dummy = new DummyAssemblyGenerator(executor, true);
            foreach (var assembly in dummy.Assemblies)
            {
                if (!assembly.MainModule.Name.EndsWith(".dll"))
                {
                    logger.LogWarning($"Fixing {assembly.MainModule.Name}'s Module Name.");
                    assembly.MainModule.Name += ".dll";
                }
            }
            Assemblies = dummy.Assemblies;
        }
    }
}
