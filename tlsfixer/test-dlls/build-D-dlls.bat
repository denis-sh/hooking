@echo off
echo ----- Building D DLLs -----
cd tlsfixer\test-dlls
set PATH=D:\D\dmd2head\windows\bin;%PATH%
for /l %%i in (1,1,3) do (
    echo 102%%i > tlsVarDesiredValue
    dmd dllmain.d -J. -oftest-D-%%i.dll -L/IMPLIB:test-D-%%i.lib ..\..\def.def || goto reportError
)
del *.obj && del tlsVarDesiredValue


goto noError
:reportError
echo Building D DLLs failed!
:noError
