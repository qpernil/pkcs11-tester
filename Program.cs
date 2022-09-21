using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;

namespace Pkcs11Tester
{
    static class Program
    {
        static IntPtr CustomDllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? dllImportSearchPath)
        {
            Console.WriteLine($"Mapping {libraryName}");
            return NativeLibrary.Load(libraryName, assembly, dllImportSearchPath);
        }
        static ICkRsaPkcsPssParams CreatePssParams(this Pkcs11InteropFactories factories, CKM hashAlgorithm)
        {
            switch(hashAlgorithm)
            {
                case CKM.CKM_SHA_1: return factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams((ulong)CKM.CKM_SHA_1, (ulong)CKG.CKG_MGF1_SHA1, 20);
                case CKM.CKM_SHA256: return factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams((ulong)CKM.CKM_SHA256, (ulong)CKG.CKG_MGF1_SHA256, 32);
                case CKM.CKM_SHA384: return factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams((ulong)CKM.CKM_SHA384, (ulong)CKG.CKG_MGF1_SHA384, 48);
                case CKM.CKM_SHA512: return factories.MechanismParamsFactory.CreateCkRsaPkcsPssParams((ulong)CKM.CKM_SHA512, (ulong)CKG.CKG_MGF1_SHA512, 64);
            }
            return null;
        }
        public static string GetLibraryName(string name, string path = null, string prefix = null, string ext = null)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return $"{path}{prefix}{name}{ext ?? ".dll"}";
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return $"{path}{prefix ?? "lib"}{name}{ext ?? ".dylib"}";
            else
                return $"{path}{prefix ?? "lib"}{name}{ext ?? ".so"}";
        }
        static void Main(string[] args)
        {
            //NativeLibrary.SetDllImportResolver(typeof(Pkcs11InteropFactories).Assembly, CustomDllImportResolver);
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, GetLibraryName("yubihsm_pkcs11", "/usr/local/lib/pkcs11/", ""), AppType.MultiThreaded, InitType.WithFunctionList))
            //using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, GetLibraryName("ykcs11"), AppType.MultiThreaded, InitType.WithFunctionList))
            {
                var li = lib.GetInfo();
                Console.WriteLine(li.LibraryDescription);
                Console.WriteLine(li.ManufacturerId);
                Console.WriteLine(li.LibraryVersion);
                Console.WriteLine(li.CryptokiVersion);
                Console.WriteLine();

                foreach (var slot in lib.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    Console.WriteLine($"SlotId {slot.SlotId}: '{slot.GetSlotInfo().SlotDescription}'");
                    Console.WriteLine($"SlotId {slot.SlotId}: '{slot.GetSlotInfo().ManufacturerId}'");
                    Console.WriteLine($"SlotId {slot.SlotId}: '{slot.GetSlotInfo().HardwareVersion}'");
                    Console.WriteLine($"SlotId {slot.SlotId}: '{slot.GetSlotInfo().FirmwareVersion}'");
                }

                byte[] id = null;

                foreach (var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
                {
                    Console.WriteLine($"SlotId {slot.SlotId}: '{slot.GetSlotInfo().SlotDescription}'");

                    var session = slot.OpenSession(SessionType.ReadWrite);
                    {
                        Console.WriteLine($"Session id {session.SessionId}");
                        Console.WriteLine($"Session state {session.GetSessionInfo().State}");

                        session.Login(CKU.CKU_USER, "0001password");
                        //session.Login(CKU.CKU_SO, "010203040506070801020304050607080102030405060708");
                        Console.WriteLine($"Session state {session.GetSessionInfo().State}");

                        var handle = session.GenerateKey(factories.MechanismFactory.Create(CKM.CKM_GENERIC_SECRET_KEY_GEN), new List<IObjectAttribute> {
                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (ulong)CKK.CKK_VENDOR_DEFINED | 0x59554200 | 29),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE_LEN, 16),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0 }),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "PKCS11 generated secret key"),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, true),
                        });

                        var vals = session.GetAttributeValue(handle, new List<CKA> { CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_VALUE_LEN });
                        var type = (CKK)vals[0].GetValueAsUlong();
                        id = vals[1].GetValueAsByteArray();
                        var len = vals[2].GetValueAsUlong();

                        session.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_EC_KEY_PAIR_GEN),
                            new List<IObjectAttribute> {
                                factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, new byte[]
                                    { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0 }),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "PKCS11 generated ec key"),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false),
                            },
                            new List<IObjectAttribute> {
                                factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0 }),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "PKCS11 generated ec key"),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false),
                            }, out var pub, out var priv);

                        vals = session.GetAttributeValue(pub, new List<CKA> { CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT });
                        type = (CKK)vals[0].GetValueAsUlong();
                        id = vals[1].GetValueAsByteArray();
                        var curve = vals[2].GetValueAsByteArray();
                        var point = vals[3].GetValueAsByteArray();
                        Console.WriteLine($"GenerateKeyPair public CKA_KEY_TYPE {type} CKA_ID {Convert.ToHexString(id)} CKA_EC_PARAMS {Convert.ToHexString(curve)} CKA_EC_POINT {Convert.ToHexString(point)}");

                        vals = session.GetAttributeValue(priv, new List<CKA> { CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT });
                        type = (CKK)vals[0].GetValueAsUlong();
                        id = vals[1].GetValueAsByteArray();
                        curve = vals[2].GetValueAsByteArray();
                        point = vals[3].GetValueAsByteArray();
                        Console.WriteLine($"GenerateKeyPair private CKA_KEY_TYPE {type} CKA_ID {Convert.ToHexString(id)} CKA_EC_PARAMS {Convert.ToHexString(curve)} CKA_EC_POINT {Convert.ToHexString(point)}");

                        session.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
                            new List<IObjectAttribute> {
                                factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0 }),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "PKCS11 generated rsa key"),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false),
                            },
                            new List<IObjectAttribute> {
                                factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0 }),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "PKCS11 generated rsa key"),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false),
                                factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false),
                            }, out pub, out priv);

                        vals = session.GetAttributeValue(pub, new List<CKA> { CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_MODULUS_BITS, CKA.CKA_MODULUS });
                        type = (CKK)vals[0].GetValueAsUlong();
                        id = vals[1].GetValueAsByteArray();
                        var bits = vals[2].GetValueAsUlong();
                        var mod = vals[3].GetValueAsByteArray();
                        Console.WriteLine($"GenerateKeyPair public CKA_KEY_TYPE {type} CKA_ID {Convert.ToHexString(id)} CKA_MODULUS_BITS {bits} CKA_MODULUS {Convert.ToHexString(mod)}");

                        vals = session.GetAttributeValue(priv, new List<CKA> { CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_MODULUS });
                        type = (CKK)vals[0].GetValueAsUlong();
                        id = vals[1].GetValueAsByteArray();
                        mod = vals[2].GetValueAsByteArray();
                        Console.WriteLine($"GenerateKeyPair private CKA_KEY_TYPE {type} CKA_ID {Convert.ToHexString(id)} CKA_MODULUS {Convert.ToHexString(mod)}");

                        handle = session.CreateObject(new List<IObjectAttribute> {
                            factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_COPYABLE, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_DESTROYABLE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0, 0 }),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, "PKCS11 imported ec privkey"),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN_RECOVER, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY_RECOVER, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_WRAP, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_UNWRAP, false),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, new byte[]
                                { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }),
                            factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, new byte[32]
                                { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50-20 }) });

                        vals = session.GetAttributeValue(handle, new List<CKA> { CKA.CKA_KEY_TYPE, CKA.CKA_ID, CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT });
                        type = (CKK)vals[0].GetValueAsUlong();
                        id = vals[1].GetValueAsByteArray();
                        curve = vals[2].GetValueAsByteArray();
                        point = vals[3].GetValueAsByteArray();

                        Console.WriteLine($"CreateObject CKA_KEY_TYPE {type} CKA_ID {Convert.ToHexString(id)} CKA_EC_PARAMS {Convert.ToHexString(curve)} CKA_EC_POINT {Convert.ToHexString(point)}");

                        /*
                        session.Logout();
                        Console.WriteLine($"Session state {session.GetSessionInfo().State}");
                        session.Login(CKU.CKU_USER, "123456");
                        Console.WriteLine($"Session state {session.GetSessionInfo().State}");
                        */
                        handle = session.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, id) }).Single();

                        vals = session.GetAttributeValue(handle, new List<CKA> { CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT });
                        var val = vals[0].GetValueAsByteArray();
                        Console.WriteLine($"CKA_EC_PARAMS {Convert.ToHexString(val)}");
                        val = vals[1].GetValueAsByteArray();
                        Console.WriteLine($"CKA_EC_POINT {Convert.ToHexString(val)}");

                        var sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_ECDSA_SHA256), handle, new byte[32]);
                        Console.WriteLine($"Signature length {sig.Length}");
                    }
                }

                Console.Write("Remove and reinsert YubiKey, then press ENTER to continue");
                Console.ReadLine();

                foreach (var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
                {
                    Console.WriteLine($"SlotId {slot.SlotId}: '{slot.GetSlotInfo().SlotDescription}'");

                    var session = slot.OpenSession(SessionType.ReadWrite);
                    {
                        Console.WriteLine($"Session id {session.SessionId}");
                        Console.WriteLine($"Session state {session.GetSessionInfo().State}");

                        if (session.GetSessionInfo().State != CKS.CKS_RW_USER_FUNCTIONS)
                        {
                            //session.Login(CKU.CKU_USER, "123456");
                            session.Login(CKU.CKU_USER, "0001password");
                            Console.WriteLine($"Session state {session.GetSessionInfo().State}");
                        }

                        var objs = session.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, id) });
                        
                        var sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_ECDSA_SHA256), objs[0], new byte[32]);
                        Console.WriteLine($"Signature length {sig.Length}");
                    }
                }
            }
        }
        static void xMain(string[] args)
        {
            const string path = "/usr/local/lib/libykcs11.dylib";
            //const string path = "/usr/local/lib/pkcs11/yubihsm_pkcs11.dylib";
            //const string path = "/usr/local/lib/opensc-pkcs11.so";
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, path, AppType.MultiThreaded, InitType.WithFunctionList))
            {
                var li = lib.GetInfo();
                Console.WriteLine(li.LibraryDescription);
                Console.WriteLine(li.ManufacturerId);
                Console.WriteLine(li.LibraryVersion);
                Console.WriteLine(li.CryptokiVersion);
                Console.WriteLine();

                foreach (var slot in lib.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
                {
                    Console.WriteLine($"SlotId {slot.SlotId}");
                    Console.WriteLine();

                    var sli = slot.GetSlotInfo();
                    Console.WriteLine(sli.SlotDescription);
                    Console.WriteLine(sli.FirmwareVersion);
                    Console.WriteLine(sli.HardwareVersion);
                    Console.WriteLine(sli.ManufacturerId);
                    Console.WriteLine($"{sli.SlotFlags.Flags:X}");
                    Console.WriteLine(sli.SlotFlags.HardwareSlot);
                    Console.WriteLine(sli.SlotFlags.RemovableDevice);
                    Console.WriteLine(sli.SlotFlags.TokenPresent);
                    Console.WriteLine();

                    if (!sli.SlotFlags.TokenPresent)
                        continue;

                    var ti = slot.GetTokenInfo();
                    Console.WriteLine(ti.Label);
                    Console.WriteLine(ti.Model);
                    Console.WriteLine(ti.FirmwareVersion);
                    Console.WriteLine(ti.ManufacturerId);
                    Console.WriteLine(ti.MaxRwSessionCount);
                    Console.WriteLine(ti.RwSessionCount);
                    Console.WriteLine(ti.MaxSessionCount);
                    Console.WriteLine(ti.SessionCount);
                    Console.WriteLine(ti.TotalPublicMemory);
                    Console.WriteLine(ti.FreePublicMemory);
                    Console.WriteLine(ti.TotalPrivateMemory);
                    Console.WriteLine(ti.FreePrivateMemory);
                    Console.WriteLine(ti.SerialNumber);
                    Console.WriteLine(ti.HardwareVersion);
                    Console.WriteLine(ti.MinPinLen);
                    Console.WriteLine(ti.MaxPinLen);
                    Console.WriteLine(ti.UtcTime);
                    Console.WriteLine($"{ti.TokenFlags.Flags:X}");
                    Console.WriteLine();

                    var mechList = slot.GetMechanismList();
                    Console.WriteLine($"{mechList.Count} mechanisms supported");
                    
                    foreach (var mechType in mechList)
                    {
                        var mech = slot.GetMechanismInfo(mechType);
                        Console.WriteLine($"Mech {mech.Mechanism} {mech.MechanismFlags.Flags:X} {mech.MinKeySize} {mech.MaxKeySize}");
                    }
                    Console.WriteLine();

                    //slot.InitToken("010203040506070801020304050607080102030405060708", "");

                    var session0 = slot.OpenSession(SessionType.ReadWrite);
                    /*
                    byte[] eccp256 = new byte[] {0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
                    byte[] eccp384 = new byte[] { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };

                    session0.Login(CKU.CKU_SO, "010203040506070801020304050607080102030405060708");

                    session0.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_ECDSA_KEY_PAIR_GEN),
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, eccp256) },
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0x19 }) },
                        out var pubKey, out var privKey);
                    Console.WriteLine($"Pubkey {pubKey.ObjectId}");
                    Console.WriteLine($"Privkey {privKey.ObjectId}");

                    session0.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_ECDSA_KEY_PAIR_GEN),
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, eccp384) },
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0x01 }) },
                        out pubKey, out privKey);

                    Console.WriteLine($"Pubkey {pubKey.ObjectId}");
                    Console.WriteLine($"Privkey {privKey.ObjectId}");

                    session0.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_ECDSA_KEY_PAIR_GEN),
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, eccp384) },
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0x02 }) },
                        out pubKey, out privKey);

                    Console.WriteLine($"Pubkey {pubKey.ObjectId}");
                    Console.WriteLine($"Privkey {privKey.ObjectId}");

                    session0.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_ECDSA_KEY_PAIR_GEN),
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_EC_PARAMS, eccp384) },
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0x03 }) },
                        out pubKey, out privKey);

                    Console.WriteLine($"Pubkey {pubKey.ObjectId}");
                    Console.WriteLine($"Privkey {privKey.ObjectId}");

                    session0.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048) },
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0x04 }) },
                        out pubKey, out privKey);

                    Console.WriteLine($"Pubkey {pubKey.ObjectId}");
                    Console.WriteLine($"Privkey {privKey.ObjectId}");

                    session0.Logout();
                    */
                    /*
                    var cert = session0.CreateObject(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, File.ReadAllBytes("/Users/PNilsson/Documents/Rudy.der")),
                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 1 }) });
                    Console.WriteLine($"Cert {cert.ObjectId}");

                    //session0.DestroyObject(factories.ObjectHandleFactory.Create(37));
                    
                    session0.Logout();
                    */
                    session0.Login(CKU.CKU_USER, "123456");
                    var objs1 = session0.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 4 }) });
                    var objs2 = session0.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 4 }) });

                    var bits = session0.GetAttributeValue(objs1[0], new List<CKA> { CKA.CKA_MODULUS_BITS })[0].GetValueAsUlong();

                    var sw = Stopwatch.StartNew();

                    Parallel.For(0, 7, i => {
                        var sw3 = Stopwatch.StartNew();
                        using (var session = slot.OpenSession(SessionType.ReadWrite))
                        {
                            Console.WriteLine($"Session {session.SessionId} OpenSession {sw3.Elapsed}");
                            /*
                            ti = slot.GetTokenInfo();
                            Console.WriteLine(ti.RwSessionCount);
                            Console.WriteLine(ti.SessionCount);
                            Console.WriteLine();
                            */
                            /*
                            var si = session.GetSessionInfo();
                            Console.WriteLine(si.SlotId);
                            Console.WriteLine(si.SessionId);
                            Console.WriteLine(si.State);
                            Console.WriteLine($"{si.SessionFlags.Flags:X}");
                            Console.WriteLine(si.SessionFlags.RwSession);
                            Console.WriteLine(si.SessionFlags.SerialSession);
                            Console.WriteLine();
                            */
                            //session.Login(CKU.CKU_SO, "010203040506070801020304050607080102030405060708");

                            var session2 = slot.OpenSession(SessionType.ReadOnly);

                            var data = new byte[48];
                            new Random().NextBytes(data);

                            var sw2 = Stopwatch.StartNew();
                            var sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS), objs1[0], data);
                            session.Verify(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS), objs2[0], data, sig, out var valid);
                            Console.WriteLine($"Session {session.SessionId} Sign {sw2.Elapsed} Valid {valid}");

                            sw2.Restart();
                            sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS), objs1[0], data);
                            session.Verify(factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS), objs2[0], data, sig, out valid);
                            Console.WriteLine($"Session {session.SessionId} Sign {sw2.Elapsed} Valid {valid}");

                            sw2.Restart();
                            sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_PSS, factories.CreatePssParams(CKM.CKM_SHA384)), objs1[0], data);
                            session.Verify(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_PSS, factories.CreatePssParams(CKM.CKM_SHA384)), objs2[0], data, sig, out valid);
                            Console.WriteLine($"Session {session.SessionId} Sign {sw2.Elapsed} Valid {valid}");

                            sw2.Restart();
                            sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS_PSS, factories.CreatePssParams(CKM.CKM_SHA256)), objs1[0], data);
                            session.Verify(factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS_PSS, factories.CreatePssParams(CKM.CKM_SHA256)), objs2[0], data, sig, out valid);
                            Console.WriteLine($"Session {session.SessionId} Sign {sw2.Elapsed} Valid {valid}");

                            data = new byte[bits / 8];
                            new Random().NextBytes(data);
                            data[0] &= 0x7f;

                            sw2.Restart();
                            sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_RSA_X_509), objs1[0], data);
                            session.Verify(factories.MechanismFactory.Create(CKM.CKM_RSA_X_509), objs2[0], data, sig, out valid);
                            Console.WriteLine($"Session {session.SessionId} Sign {sw2.Elapsed} Valid {valid}");
                            session2.CloseSession();
                            
                            sw2.Restart();
                            var enc = session.Encrypt(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS), objs2[0], new byte[64]);
                            Console.WriteLine($"Session {session.SessionId} Encrypt {sw2.Elapsed}");

                            sw2.Restart();
                            var dec = session.Decrypt(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS), objs1[0], enc);
                            Console.WriteLine($"Session {session.SessionId} Decrypt {sw2.Elapsed} Valid {dec.SequenceEqual(new byte[64])}");
                            
                            var objs = session.FindAllObjects(null);
                            Console.WriteLine($"Session {session.SessionId} found {objs.Count} objects");
                            Console.WriteLine();

                            foreach (var obj in objs)
                            {
                                Console.WriteLine($"ObjectId {obj.ObjectId} size {session.GetObjectSize(obj)}");

                                var attrs = session.GetAttributeValue(obj, new List<CKA> { CKA.CKA_CLASS, CKA.CKA_TOKEN, CKA.CKA_MODIFIABLE, CKA.CKA_LABEL, CKA.CKA_ID,
                                CKA.CKA_KEY_TYPE, CKA.CKA_CERTIFICATE_TYPE, CKA.CKA_PRIVATE, CKA.CKA_LOCAL, CKA.CKA_SENSITIVE, CKA.CKA_ALWAYS_SENSITIVE, CKA.CKA_MODULUS_BITS,
                                CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT, CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT, CKA.CKA_VALUE, CKA.CKA_APPLICATION, CKA.CKA_OBJECT_ID,
                                CKA.CKA_EXTRACTABLE, CKA.CKA_NEVER_EXTRACTABLE, CKA.CKA_SUBJECT, CKA.CKA_ISSUER, CKA.CKA_SERIAL_NUMBER });

                                foreach (var attr in attrs)
                                {
                                    if (!attr.CannotBeRead)
                                    {
                                        var val = attr.GetValueAsByteArray();
                                        var type = (CKA)attr.Type;
                                        if (type == CKA.CKA_LABEL || type == CKA.CKA_APPLICATION)
                                        {
                                            Console.WriteLine($"{type} {val.Length}: {BitConverter.ToString(val).Replace("-", "")} {attr.GetValueAsString()}");
                                        }
                                        else
                                        {
                                            if (obj.ObjectId == 61 && type == CKA.CKA_VALUE)
                                            {
                                                File.WriteAllBytes("attest.der", val);
                                            }
                                            if (obj.ObjectId == 65 && type == CKA.CKA_VALUE)
                                            {
                                                File.WriteAllBytes("attest9e.der", val);
                                            }
                                            Console.WriteLine($"{type} {val.Length}: {BitConverter.ToString(val).Replace("-", "")}");
                                        }
                                    }
                                }
                                Console.WriteLine();
                            }
                        }
                    });
                    session0.CloseSession();
                    Console.WriteLine(sw.Elapsed);
                }
            }
        }
    }
}
