using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nektra.Deviare2;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Threading;

namespace SocketHook
{
    class Program
    {
        static string IPtoString(byte[] ip)
        {
            return string.Format("{0}.{1}.{2}.{3}", ip[0], ip[1], ip[2], ip[3]);
        }
        static byte[] StringtoIP(string ip)
        {
            byte[] ret = new byte[4];
            var ips = ip.Split('.');
            ret[0] = byte.Parse(ips[0]);
            ret[1] = byte.Parse(ips[1]);
            ret[2] = byte.Parse(ips[2]);
            ret[3] = byte.Parse(ips[3]);
            return ret;
        }
        static ushort PortToUShort(byte[] port)
        {
            return (ushort)(port[0] * 256 + port[1]);
        }
        static byte[] UShorttoPort(ushort port)
        {
            return new byte[]{(byte)(port/256), (byte)(port%256)};
        }
        public static void OnConnectCalled(NktHook hook, NktProcess process, NktHookCallInfo hookCallInfo)
        {
            /*
            struct sockaddr {
                ushort  sa_family;
                char    sa_data[14];
            };
            */
            INktParamsEnum pms = hookCallInfo.Params();
            INktParam p;

            p = pms.GetAt(1); //get the second param (const struct sockaddr *name)
            if (p.IsNullPointer == false)
            {
                INktParam pC;
                ushort sa_family;

                //if not null, analyze it
                p = p.Evaluate(); //now p becomes the struct itself not anymore a pointer to

                pC = p.Field(0);
                sa_family = pC.get_UShortValAt(0);

                try
                {
                    pC = p.Field(1);
                    byte[] bytes_port = new byte[]{pC.get_ByteValAt(0), pC.get_ByteValAt(1)};
                    ushort port = PortToUShort(bytes_port);
                    Console.WriteLine("Port: {0}", port);

                    byte[] ip = new byte[] { pC.get_ByteValAt(2), pC.get_ByteValAt(3), pC.get_ByteValAt(4), pC.get_ByteValAt(5) };
                    string detected_ip = IPtoString(ip);
                    Console.WriteLine("IP: {0}", detected_ip);
                    if (bind_ip == "0.0.0.0" || bind_ip == "*" || IPtoString(ip) == bind_ip)  // Match rule IP
                    {
                        if (bind_port == 0 || bind_port == port)  // Match rule Port
                        {
                            byte[] target_ip = StringtoIP(forward_ip);
                            pC.set_ByteValAt(2, target_ip[0]);
                            pC.set_ByteValAt(3, target_ip[1]);
                            pC.set_ByteValAt(4, target_ip[2]);
                            pC.set_ByteValAt(5, target_ip[3]);
                            if (forward_port != 0)
                            {
                                byte[] forward_port_change = UShorttoPort(forward_port);
                                pC.set_ByteValAt(0, forward_port_change[0]);
                                pC.set_ByteValAt(1, forward_port_change[1]);
                            }
                            Console.WriteLine("Redirect From {0}:{1} to {1}", detected_ip, (bind_port==0)?'*':bind_port, forward_ip, (forward_port==0)?'*':forward_port);
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error {0}", e);
                    throw e;
                }
            }
        }

        static string bind_ip;
        static ushort bind_port = 0;
        static string forward_ip;
        static ushort forward_port = 0;

        static void Main(string[] args)
        {
            var dictionary = args.Select(a => a.Split(new[] { '=' }, 2))
                     .GroupBy(a => a[0], a => a.Length == 2 ? a[1] : null)
                     .ToDictionary(g => g.Key, g => g.FirstOrDefault());
            if (!dictionary.ContainsKey("s") || !dictionary.ContainsKey("d") || !dictionary.ContainsKey("p"))
            {
                Console.Error.WriteLine("Please select s=<bind>:<bind_port> d=<forward>:<forward_port>.");
                Environment.Exit(1);
            }
            string program = dictionary["p"];
            var bind = dictionary["s"].Split(':');
            bind_ip = bind[0];
            if (bind.Length > 1)
            {
                bind_port = ushort.Parse(bind[1]);
            }
            var forward = dictionary["d"].Split(':');
            forward_ip = forward[0];
            if (forward.Length > 1)
            {
                forward_port = ushort.Parse(forward[1]);
            }

            SockHook sockhook = new SockHook();
            sockhook.InitializeSpyMgr();
            bool success = sockhook.HookProcess(program);
            sockhook.OnConnectCalled += new DNktSpyMgrEvents_OnFunctionCalledEventHandler(OnConnectCalled);
            if (!success)
                Console.WriteLine("Hook unsuccess");
            while (true)
            {
                Thread.Sleep(1);
            }
        }
    }
}
