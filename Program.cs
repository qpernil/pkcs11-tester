using System;
using System.Collections.Generic;
using System.IO;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace foo
{
    class Program
    {
        static void Main(string[] args)
        {
            const string path = "libykcs11.1.dylib";
            const string _path = "opensc-pkcs11.so";
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();
            using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, path, AppType.MultiThreaded))
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
                    Console.WriteLine(ti.SerialNumber);
                    Console.WriteLine(ti.HardwareVersion);
                    Console.WriteLine(ti.MinPinLen);
                    Console.WriteLine(ti.MaxPinLen);
                    Console.WriteLine(ti.UtcTime);
                    Console.WriteLine($"{ti.TokenFlags.Flags:X}");
                    Console.WriteLine();

                    slot.OpenSession(SessionType.ReadWrite);
                    slot.OpenSession(SessionType.ReadWrite);
                    slot.OpenSession(SessionType.ReadWrite);
                    slot.CloseAllSessions();

                    using (var session = slot.OpenSession(SessionType.ReadWrite))
                    {
                        var ti2 = slot.GetTokenInfo();
                        Console.WriteLine(ti2.MaxRwSessionCount);
                        Console.WriteLine(ti2.RwSessionCount);
                        Console.WriteLine(ti2.MaxSessionCount);
                        Console.WriteLine(ti2.SessionCount);
                        Console.WriteLine();

                        var si = session.GetSessionInfo();
                        Console.WriteLine(si.SlotId);
                        Console.WriteLine(si.SessionId);
                        Console.WriteLine(si.State);
                        Console.WriteLine($"{si.SessionFlags.Flags:X}");
                        Console.WriteLine(si.SessionFlags.RwSession);
                        Console.WriteLine(si.SessionFlags.SerialSession);
                        Console.WriteLine();
                        
                        using(var session2 = slot.OpenSession(SessionType.ReadOnly))
                        {
                            var si2 = session2.GetSessionInfo();
                            Console.WriteLine(si2.SlotId);
                            Console.WriteLine(si2.SessionId);
                            Console.WriteLine(si2.State);
                            Console.WriteLine($"{si2.SessionFlags.Flags:X}");
                            Console.WriteLine(si2.SessionFlags.RwSession);
                            Console.WriteLine(si2.SessionFlags.SerialSession);
                            Console.WriteLine();
                            using (var session3 = slot.OpenSession(SessionType.ReadOnly))
                            {
                                var si3 = session3.GetSessionInfo();
                                Console.WriteLine(si3.SlotId);
                                Console.WriteLine(si3.SessionId);
                                Console.WriteLine(si3.State);
                                Console.WriteLine($"{si3.SessionFlags.Flags:X}");
                                Console.WriteLine(si3.SessionFlags.RwSession);
                                Console.WriteLine(si3.SessionFlags.SerialSession);
                                Console.WriteLine();
                            }
                        }
                        
                        session.Login(CKU.CKU_USER, "123456");
                        //session.Login(CKU.CKU_SO, "010203040506070801020304050607080102030405060708");
                        Console.WriteLine(session.GetSessionInfo().State);
                        /*
                        session.GenerateKeyPair(factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN),
                            new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                                                         factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                                                         factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 2048),
                                                         factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 4 }) },
                            new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                         factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA) },
                            out var pubKey, out var privKey);

                        Console.WriteLine($"Pubkey {pubKey.ObjectId}");
                        Console.WriteLine($"Privkey {privKey.ObjectId}");

                        var cert = session.CreateObject(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                                                         factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, File.ReadAllBytes("/Users/PNilsson/Documents/Rudy.der")),
                                                         factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 1 }) });
                        Console.WriteLine($"Cert {cert.ObjectId}");

                        session.DestroyObject(factories.ObjectHandleFactory.Create(37));
                        */

                        var objs = session.FindAllObjects(new List<IObjectAttribute>{factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true)/*, factories.ObjectAttributeFactory.Create(CKA.CKA_ID, new byte[] { 3 })*/ });
                        Console.WriteLine(objs.Count);
                        Console.WriteLine();

                        //continue;

                        foreach (var obj in objs)
                        {
                            Console.WriteLine($"ObjectId {obj.ObjectId}");
                            var attrs = session.GetAttributeValue(obj, new List<CKA> { CKA.CKA_CLASS, CKA.CKA_TOKEN, CKA.CKA_LABEL, CKA.CKA_ID,
                                CKA.CKA_KEY_TYPE, CKA.CKA_MODIFIABLE, CKA.CKA_PRIVATE, CKA.CKA_LOCAL, CKA.CKA_SENSITIVE, CKA.CKA_MODULUS_BITS,
                                CKA.CKA_MODULUS, CKA.CKA_PUBLIC_EXPONENT, CKA.CKA_EC_PARAMS, CKA.CKA_EC_POINT, CKA.CKA_VALUE });
                            foreach (var attr in attrs)
                            {
                                if(!attr.CannotBeRead)
                                {
                                    var val = attr.GetValueAsByteArray();
                                    var type = (CKA)attr.Type;
                                    Console.Write($"{type} {val.Length}: ");
                                    foreach(var b in val)
                                    {
                                        Console.Write($"{b:X2}");
                                    }
                                    if(type == CKA.CKA_LABEL)
                                    {
                                        Console.WriteLine($" {attr.GetValueAsString()}");
                                    }
                                    else
                                    {
                                        Console.WriteLine();
                                    }
                                }
                            }
                            Console.WriteLine();
                        }
                    }
                }
            }         
        }
    }
}
