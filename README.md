# SocketHook
SocketHook written in C#, Only support for Windows (32 bits application)


## How to use
1. Run RegisterCOMObjects.bat (as admin)
2. Run HookAPI.exe with parameter p=&lt;process.exe&gt; s=&lt;bind_address:port&gt; d=&lt;forward_address:port&gt;
(bind_address can replace with 0.0.0.0, port can be blank)

### Example parameters
HookAPI.exe p=program.exe s=0.0.0.0 d=127.0.0.1
HookAPI.exe p=program.exe s=192.168.0.1 d=192.168.0.2
HookAPI.exe p=program.exe s=192.168.0.1:8000 d=192.168.0.2
HookAPI.exe p=program.exe s=192.168.0.1:8000 d=192.168.0.2:9000
HookAPI.exe p=program.exe s=0.0.0.0:8000 d=192.168.0.2:9000
