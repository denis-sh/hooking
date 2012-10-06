/** Functions for injecting a DLL into a process

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.dllinjector;

import core.sys.windows.windows;
import std.utf;
import std.exception;


static assert(size_t.sizeof == 4);

void launchWithDll(string file, string arguments, string dllName, bool wait = true)
in { assert(file); }
body
{
	STARTUPINFOW info = { STARTUPINFOW.sizeof };
	PROCESS_INFORMATION processInfo;
	auto fileW = toUTF16z(file);
	enforce(CreateProcessW(fileW, arguments ? toUTF16(arguments ~ '\0').dup.ptr : null,
		null, null, TRUE, CREATE_SUSPENDED/* | CREATE_NEW_CONSOLE*/, null, null, &info, &processInfo));

	size_t entryPoint = getEntryPoint(fileW, processInfo.hProcess);

	
	ubyte[5 + 2] originCode,
		newCode = cast(const(ubyte)[]) x"E9 00000000 EB FE"; // JMP rel32; JMP $-2;

	// Save old code and make memory writeable
	enforce(ReadProcessMemory(processInfo.hProcess, cast(void*) entryPoint, originCode.ptr, originCode.length, null));
	makeWriteable(processInfo.hProcess, cast(void*)entryPoint, originCode.length);

	// Let Windows initialize its stuff
	enforce(WriteProcessMemory(processInfo.hProcess, cast(void*) entryPoint, x"EB FE".ptr /* JMP $-2 */, 2, null));
	enforce(FlushInstructionCache(processInfo.hProcess, cast(void*) entryPoint, 2));
	executeUntil(processInfo.hThread, entryPoint);

	// Allocate and fill remote memory for code and data
	size_t executeStart, remotePtr = allocateRemoteCodeAndData(processInfo.hProcess, dllName, entryPoint + 5, executeStart);
	*cast(size_t*)(newCode.ptr + 1) = executeStart - (entryPoint + 5);

	// Load our DLL
	enforce(WriteProcessMemory(processInfo.hProcess, cast(void*) entryPoint, newCode.ptr, newCode.length, null));
	enforce(FlushInstructionCache(processInfo.hProcess, cast(void*) entryPoint, newCode.length));
	executeUntil(processInfo.hThread, entryPoint + newCode.length - 2);

	// Free remote memory
	enforce(VirtualFreeEx(processInfo.hProcess, cast(void*) remotePtr, 0, MEM_RELEASE));

	
	auto hPsapi = LoadLibraryA("Psapi");
	
	auto EnumProcessModules = cast(EnumProcessModulesType) GetProcAddress(hPsapi, "EnumProcessModules");
	
	HMODULE[256] staticHmoduleBuff;
	HMODULE[] modules = staticHmoduleBuff;
	size_t needed;
	enforce(EnumProcessModules(processInfo.hProcess, staticHmoduleBuff.ptr, staticHmoduleBuff.sizeof, &needed));
	assert(needed % HMODULE.sizeof == 0);
	if(needed > staticHmoduleBuff.sizeof)
	{
		modules = new HMODULE[needed / HMODULE.sizeof];
		enforce(EnumProcessModules(processInfo.hProcess, modules.ptr, modules.length, &needed));
		enforce(needed == modules.length * HMODULE.sizeof);
	}

	// Restore origin code
	enforce(WriteProcessMemory(processInfo.hProcess, cast(void*) entryPoint, originCode.ptr, originCode.length, null));
	enforce(FlushInstructionCache(processInfo.hProcess, cast(void*) entryPoint, originCode.length));

	// Restore EIP and resume thread
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	enforce(GetThreadContext(processInfo.hThread, &context));
	context.Eip = entryPoint;
	assert(context.ContextFlags == CONTEXT_CONTROL);
	enforce(SetThreadContext(processInfo.hThread, &context));
	enforce(ResumeThread(processInfo.hThread) != -1);

	if(wait)
		WaitForSingleObject(processInfo.hProcess, INFINITE);
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
}


private:

size_t allocateRemoteCodeAndData(HANDLE hProcess, string dllName, size_t jmpAddress, out size_t executeStart)
{
	wstring strW = toUTF16(dllName);
	auto buff = new ubyte[(strW.length + 1) * 2 + 5 + 5 + 5];
	ubyte* ptr = buff.ptr;

	void write(T)(in T[] tarr...)
	{
		auto barr = cast(const(ubyte)[]) tarr;
		ptr[0 .. barr.length] = barr;
		ptr += barr.length;
	}

	// Write data
	write(strW);
	write("\0"w);

	// Allocate memory in other process
	immutable size_t remotePtr = cast(size_t) enforce
		(VirtualAllocEx(hProcess, null, buff.length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	executeStart = remotePtr + (ptr - buff.ptr);

	// Write code
	write(x"68"); // PUSH imm32
	write(remotePtr);
	write(x"E8"); // CALL rel32
	write(
		cast(size_t) enforce(GetProcAddress(GetModuleHandleW("kernel32.dll"), "LoadLibraryW")) -
		(remotePtr + (ptr - buff.ptr) + 4));

	write(x"E9"); // JMP rel32
	write(jmpAddress - (remotePtr + (ptr - buff.ptr) + 4));


	assert(ptr == buff.ptr + buff.length);
	enforce(WriteProcessMemory(hProcess, cast(void*) remotePtr, buff.ptr, buff.length, null));
	enforce(FlushInstructionCache(hProcess, cast(void*) remotePtr, buff.length));

	return remotePtr;
}


// WinAPI helpers
// --------------------------------------------------

DWORD getEntryPoint(LPCWSTR file, HANDLE hProcess)
{
	void* pExe;
	{
		HANDLE hFile = CreateFileW(file, GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE, null,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
		enforce(hFile != INVALID_HANDLE_VALUE);
		scope(exit) enforce(CloseHandle(hFile));

		HANDLE hFileMap = enforce(CreateFileMappingA(hFile, null, PAGE_READONLY, 0, 0, null));
		scope(exit) enforce(CloseHandle(hFileMap));

		pExe = enforce(MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0));
	}
	scope(exit) enforce(UnmapViewOfFile(pExe));

	auto RtlImageNtHeader = cast(RtlImageNtHeaderType)
		GetProcAddress(LoadLibraryA("ntdll"), "RtlImageNtHeader");

	const ntOptionalHeader = RtlImageNtHeader(pExe) + 24 /* OptionalHeader */;
	return *cast(size_t*) (ntOptionalHeader + 28 /* ImageBase */) +
		*cast(size_t*) (ntOptionalHeader + 16 /* AddressOfEntryPoint */);
}

DWORD makeWriteable(HANDLE hProcess, void* ptr, size_t size)
{
	//enforce(IsBadWritePtr(ptr, size), "Alreasy accessed changed by some program");

	MEMORY_BASIC_INFORMATION mbi;
	enforce(VirtualQueryEx(hProcess, ptr, &mbi, mbi.sizeof));
	auto tt = mbi.Protect;
	mbi.Protect &= ~(PAGE_READONLY|PAGE_EXECUTE_READ);
	mbi.Protect |= PAGE_EXECUTE_READWRITE;
	DWORD dwOld;
	enforce(VirtualProtectEx(hProcess, ptr, size, mbi.Protect, &dwOld));
	return dwOld;
}

void executeUntil(HANDLE thread, size_t address)
{
	enforce(ResumeThread(thread) != -1);
	for(size_t i = 0; ;++i)
	{
		Sleep(20);
		CONTEXT context;
		context.ContextFlags = CONTEXT_CONTROL;
		enforce(GetThreadContext(thread, &context));
		if(context.Eip == address)
			break;
		enforce(i < 50);
	}
	enforce(SuspendThread(thread) != -1);
}


// WinAPI
// --------------------------------------------------

struct STARTUPINFOW
{
	DWORD   cb;
	LPWSTR  lpReserved;
	LPWSTR  lpDesktop;
	LPWSTR  lpTitle;
	DWORD   dwX;
	DWORD   dwY;
	DWORD   dwXSize;
	DWORD   dwYSize;
	DWORD   dwXCountChars;
	DWORD   dwYCountChars;
	DWORD   dwFillAttribute;
	DWORD   dwFlags;
	WORD    wShowWindow;
	WORD    cbReserved2;
	LPBYTE  lpReserved2;
	HANDLE  hStdInput;
	HANDLE  hStdOutput;
	HANDLE  hStdError;
}

struct PROCESS_INFORMATION
{
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
}

extern(Windows)
{
	extern BOOL CreateProcessW(
		LPCWSTR lpApplicationName,
		LPWSTR lpCommandLine, // The Unicode version of this function, CreateProcessW, can modify the contents of this string.
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL bInheritHandles,
		DWORD dwCreationFlags,
		LPVOID lpEnvironment,
		LPCWSTR lpCurrentDirectory,
		STARTUPINFOW* lpStartupInfo,
		PROCESS_INFORMATION* lpProcessInformation
	);

	enum
	{
		CREATE_SUSPENDED    = 0x00000004,
		CREATE_NEW_CONSOLE  = 0x00000010,
	}

	alias BOOL function(
		HANDLE hProcess,
		HMODULE *lphModule,
		DWORD cb,
		LPDWORD lpcbNeeded
	) EnumProcessModulesType;

	alias const(void)* function(in PVOID ModuleAddress) RtlImageNtHeaderType;

	extern BOOL ReadProcessMemory(
		HANDLE hProcess,
		LPCVOID lpBaseAddress,
		LPVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T *lpNumberOfBytesRead
	);

	extern BOOL WriteProcessMemory(
		HANDLE hProcess,
		LPVOID lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T *lpNumberOfBytesWritten
	);
}
