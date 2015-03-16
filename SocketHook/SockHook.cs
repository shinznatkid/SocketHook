using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Nektra.Deviare2;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace SocketHook
{

    class SockHook
    {
        public NktSpyMgr spyMgr = new NktSpyMgr();
        public NktProcess process;

        public System.Collections.Stack stackFunctions = new System.Collections.Stack();

        public delegate void newFunctionHandler();
        public event DNktSpyMgrEvents_OnFunctionCalledEventHandler OnConnectCalled;

        public bool InitializeSpyMgr()
        {
            int res = spyMgr.Initialize();

            if (res == 0)
            {
                spyMgr.OnFunctionCalled += new DNktSpyMgrEvents_OnFunctionCalledEventHandler(OnFunctionCalled);
                return true;
            }
            return false;
        }

        private bool HookFunction(NktProcess process, string function, eNktHookFlags flag)
        {
            NktHook hook = spyMgr.CreateHook(function, (int)flag);
            
            if (hook == null)
                return false;
            try
            {
                hook.Hook(true);
                Console.WriteLine("Hooked {0}", function);
                hook.Attach(process, true);// false);
                Console.WriteLine("Attach {0}", function);
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
            return true;
        }

        public bool UnHook()
        {
            if (process == null)
                return false;

            bool unhooked = false;

            foreach (NktHook hook in spyMgr.Hooks())
            {
                hook.Unhook(false);

                if (!unhooked)
                    Console.WriteLine("Unhooking " + process.Name);
                unhooked = true;
            }

            return unhooked;
        }

        public bool HookProcess(int pid)
        {
            for (int i = 0; i < spyMgr.Processes().Count; i++)
            {
                NktProcess p = (NktProcess) spyMgr.Processes().GetAt(i);
                if (p.Id == pid)
                    return HookProcess(p);
            }

            return false;
        }

        public bool HookProcess(string proccessName)
        {
            NktProcessesEnum enumProcess = spyMgr.Processes();
            NktProcess tempProcess = enumProcess.First();
            while (tempProcess != null)
            {
                if (tempProcess.Name.Equals(proccessName, StringComparison.InvariantCultureIgnoreCase))
                {
                    Console.WriteLine("Found process {0}", proccessName);
                    return HookProcess(tempProcess);
                }
                tempProcess = enumProcess.Next();
            }
            return false;
        }

        public bool HookProcess(NktProcess process)
        {
            this.UnHook();

            bool result = false;
            result = HookFunction(process, "kernel32.dll!CreateFileW", eNktHookFlags.flgOnlyPreCall);
            if (result == false)
                return result;

            result = HookFunction(process, "WS2_32.dll!connect", eNktHookFlags.flgOnlyPreCall);
            if (result == false)
                return result;


            if (result == false)
                return result;

            this.process = process;
           return true;
        }

        public void OnFunctionCalled(NktHook hook, NktProcess process, NktHookCallInfo hookCallInfo)
        {
            string function = hook.FunctionName.ToLower();
            Console.WriteLine("Called function {0}", function);

            if (function == "WS2_32.dll!connect".ToLower())
            {
                OnConnectCalled(hook, process, hookCallInfo);
            }
            

        }
    }
}