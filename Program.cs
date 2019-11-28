using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Pkcs11Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            const string path = "libykcs11.1.dylib";
            const string _path = "opensc-pkcs11.so";
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
                    Console.WriteLine($"SlotId {slot.SlotId:X}");
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

                    //slot.InitToken("010203040506070801020304050607080102030405060708", "");

                    var s1 = slot.OpenSession(SessionType.ReadWrite);

                    /*
                    s1.Login(CKU.CKU_SO, "010203040506070801020304050607080102030405060708");
                    s1.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                                                             factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                                                             factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048),
                                                             factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 0x19 }) },
                        new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                             factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA) },
                        out var pubKey, out var privKey);

                    Console.WriteLine($"Pubkey {pubKey.ObjectId}");
                    Console.WriteLine($"Privkey {privKey.ObjectId}");

                    //s1.DestroyObject(pubKey);
                    //s1.DestroyObject(privKey);

                    s1.Logout();
                    */
                    /*
                    var cert = s1.CreateObject(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, File.ReadAllBytes("/Users/PNilsson/Documents/Rudy.der")),
                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 1 }) });
                    Console.WriteLine($"Cert {cert.ObjectId}");

                    s1.DestroyObject(factories.ObjectHandleFactory.Create(37));
                    
                    s1.Logout();
                    */
                    s1.Login(CKU.CKU_USER, "123456");
                    var objs1 = s1.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 2 }) });
                    s1.CloseSession();
                    var sw = Stopwatch.StartNew();

                    Parallel.For(0, 8, _ => {
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
                            session.Login(CKU.CKU_USER, "123456");
                            //session.Login(CKU.CKU_SO, "010203040506070801020304050607080102030405060708");

                            var session2 = slot.OpenSession(SessionType.ReadOnly);
                            var sw2 = Stopwatch.StartNew();
                            var sig = session.Sign(factories.MechanismFactory.Create(CKM.CKM_ECDSA), objs1[0], new byte[32]);
                            Console.WriteLine($"Session {session.SessionId} Sign {sw2.Elapsed}");
                            session2.CloseSession();

                            var objs = session.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true)/*, factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 3 })*/ });
                            Console.WriteLine($"Session {session.SessionId} found {objs.Count} CKA_TOKEN objects");
                            Console.WriteLine();

                            foreach (var obj in objs)
                            {
                                Console.WriteLine($"ObjectId {obj.ObjectId} size {session.GetObjectSize(obj)}");
                                var attrs = session.GetAttributeValue(obj, new List<CKA> { CKA.CKA_CLASS, CKA.CKA_TOKEN, CKA.CKA_MODIFIABLE, CKA.CKA_LABEL, CKA.CKA_ID,
                                CKA.CKA_KEY_TYPE, CKA.CKA_CERTIFICATE_TYPE, CKA.CKA_PRIVATE, CKA.CKA_LOCAL, CKA.CKA_SENSITIVE, CKA.CKA_MODULUS_BITS, CKA.CKA_MODULUS,
                                CKA.CKA_PUBLIC_EXPONENT, CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT, CKA.CKA_VALUE, CKA.CKA_APPLICATION, CKA.CKA_OBJECT_ID,
                                CKA.CKA_SUBJECT, CKA.CKA_ISSUER, CKA.CKA_SERIAL_NUMBER });
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
                                            if(obj.ObjectId == 63 && type == CKA.CKA_VALUE)
                                            {
                                                File.WriteAllBytes("cert.der", val);
                                            }
                                            Console.WriteLine($"{type} {val.Length}: {BitConverter.ToString(val).Replace("-", "")}");
                                        }
                                    }
                                }
                                Console.WriteLine();
                            }
                        }
                    });
                    Console.WriteLine(sw.Elapsed);
                }
            }
        }
    }
}
