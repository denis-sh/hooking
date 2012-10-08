@echo off
echo ----- Building C DLLs -----
cd tlsfixer\test-dlls
call "%ProgramFiles%\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" x86

rem /O2 Creates fast code.
rem /Oi Generates intrinsic functions.
rem /GL Enables whole program optimization.
rem /EH (Exception Handling Model)
rem    catches C++ exceptions only and tells the compiler to assume
rem    that extern C functions never throw a C++ exception
rem /MD Creates a multithreaded DLL using MSVCRT.lib.
rem /MT Creates a multithreaded executable file using LIBCMT.lib.
rem /Gy Enables function-level linking.
rem /Fo Creates an object file.
rem /W3 warning level
rem /c Compiles without linking.
rem /Zi Generates complete debugging information.
rem /TP Specifies a C++ source file.


cl /O2 /Oi /GL /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_USRDLL" /D "TESTCDLLS_EXPORTS" /D "_WINDLL" /D "_UNICODE" /D "UNICODE" /EHsc /MT /Gy /W3 /c /Zi /TP dllmain.cpp /nologo /errorReport:prompt || echo Error && pause


link /OUT:test-C.dll /INCREMENTAL:NO /DLL /DEBUG /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /LTCG /DYNAMICBASE /NXCOMPAT /MACHINE:X86 kernel32.lib dllmain.obj /NOLOGO /ERRORREPORT:PROMPT || echo Error && pause

del *.obj && del *.exp && del *.pdb
if exist test-C-COFF.lib del test-C-COFF.lib
rename test-C.lib test-C-COFF.lib
