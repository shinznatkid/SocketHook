@ECHO OFF
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
IF '%errorlevel%' == '0' GOTO hasAdmin

ECHO Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
ECHO UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
EXIT /B

:hasAdmin
IF EXIST "%temp%\getadmin.vbs" ( DEL "%temp%\getadmin.vbs" )

ECHO Registering DeviareCOM.dll and DeviareCOM64.dll...
regsvr32 /s "%~dp0\DeviareCOM.dll"
regsvr32 /s "%~dp0\DeviareCOM64.dll"
PAUSE
