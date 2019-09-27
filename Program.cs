using System;
using System.Collections.Generic;
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
            using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, path, AppType.SingleThreaded))
            {
                var li = lib.GetInfo();
                Console.WriteLine(li.LibraryDescription);
                Console.WriteLine(li.ManufacturerId);
                Console.WriteLine(li.LibraryVersion);
                Console.WriteLine(li.CryptokiVersion);
                Console.WriteLine();

                foreach(var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
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

                    var ti = slot.GetTokenInfo();
                    Console.WriteLine(ti.Model);
                    Console.WriteLine(ti.MaxRwSessionCount);
                    Console.WriteLine(ti.RwSessionCount);
                    Console.WriteLine(ti.MaxSessionCount);
                    Console.WriteLine(ti.SessionCount);
                    Console.WriteLine(ti.FirmwareVersion);
                    Console.WriteLine(ti.SerialNumber);
                    Console.WriteLine(ti.HardwareVersion);
                    Console.WriteLine($"{ti.TokenFlags.Flags:X}");
                    Console.WriteLine();

                    using (var session = slot.OpenSession(SessionType.ReadOnly))
                    {
                        var si = session.GetSessionInfo();
                        Console.WriteLine(si.SlotId);
                        Console.WriteLine(si.SessionId);
                        Console.WriteLine(si.State);
                        Console.WriteLine($"{si.SessionFlags.Flags:X}");
                        Console.WriteLine(si.SessionFlags.RwSession);
                        Console.WriteLine(si.SessionFlags.SerialSession);
                        Console.WriteLine();

                        session.Login(CKU.CKU_USER, "123456");
                        Console.WriteLine(session.GetSessionInfo().State);

                        var objs = session.FindAllObjects(new List<IObjectAttribute>{factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true)/*, factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_DATA)*/});
                        Console.WriteLine(objs.Count);
                        Console.WriteLine();

                        foreach (var obj in objs)
                        {
                            Console.WriteLine($"ObjectId {obj.ObjectId:X}");
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
