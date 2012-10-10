/** Functions for process manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.process;

import core.sys.windows.windows;
import std.utf;
import std.exception;

import hooking.windows.thread;


static assert(size_t.sizeof == 4);

alias size_t RemoteAddress;

struct Process
{
	private PROCESS_INFORMATION info;

	this(string file, string arguments, bool launchSuspended, bool createNewConsole = false)
	in { assert(file); }
	body
	{
		DWORD creationFlags = 0;
		if(launchSuspended)
			creationFlags |= CREATE_SUSPENDED;
		if(createNewConsole)
			creationFlags |= CREATE_NEW_CONSOLE;
		STARTUPINFOW startupInfo = { STARTUPINFOW.sizeof };
		enforce(CreateProcessW(toUTF16z(file), arguments ? toUTF16(arguments ~ '\0').dup.ptr : null,
			null, null, TRUE, creationFlags, null, null, &startupInfo, &info));
	}

	@property Thread primaryThread() { return Thread(info.hThread); }

	/// Returns previous access protection of the first page in the specified region
	DWORD changeMemoryProtection(RemoteAddress address, size_t size, DWORD newProtection)
	{
		DWORD oldProtection;
		enforce(VirtualProtectEx(info.hProcess, cast(LPVOID) address, size, newProtection, &oldProtection));
		return oldProtection;
	}

	void readMemory(RemoteAddress baseAddress, void[] buff)
	{
		enforce(ReadProcessMemory(info.hProcess, cast(LPCVOID) baseAddress, buff.ptr, buff.length, null));
	}

	void writeMemory(RemoteAddress baseAddress, in void[] buff, bool flushInstructionCache = false)
	{
		enforce(WriteProcessMemory(info.hProcess, cast(LPVOID) baseAddress, buff.ptr, buff.length, null));
		if(flushInstructionCache)
			enforce(FlushInstructionCache(info.hProcess, cast(LPVOID) baseAddress, buff.length));
	}

	void initializeWindowsStuff()
	{
		RemoteAddress entryPoint = getEntryPoint(info.hProcess);

		enum loopCode = x"EB FE"; // JMP $-2

		// Change memory protection (before reading because it can be PAGE_EXECUTE)
		DWORD oldProtection = changeMemoryProtection(entryPoint, loopCode.length, PAGE_EXECUTE_READWRITE);
		enforce(oldProtection & 0xF0); // Expect some PAGE_EXECUTE_* constant

		ubyte[loopCode.length] originCode;
		readMemory(entryPoint, originCode);         // Save origin code
		writeMemory(entryPoint, loopCode, true);    // Write new loop code (and flush instruction cache)
		mainThread.executeUntil(entryPoint);        // Let Windows initialize its stuff
		writeMemory(entryPoint, originCode, true);  // Restore origin code

		// Restore origin memory protection
		enforce(changeMemoryProtection(entryPoint, loopCode.length, oldProtection) == PAGE_EXECUTE_READWRITE);
	}

	void resumeWithDll(string dllName)
	{
		RemoteAddress entryPoint = getEntryPoint(info.hProcess);


		ubyte[5 + 2] originCode,
			newCode = cast(const(ubyte)[]) x"E9 00000000 EB FE"; // JMP rel32; JMP $-2;

		// Change memory protection (before reading because it can be PAGE_EXECUTE)
		DWORD oldProtection = changeMemoryProtection(entryPoint, originCode.length, PAGE_EXECUTE_READWRITE);
		enforce(oldProtection & 0xF0); // Expect some PAGE_EXECUTE_* constant

		// Save origin code
		readMemory(entryPoint, originCode);

		// Let Windows initialize its stuff
		writeMemory(entryPoint, x"EB FE" /* JMP $-2 */, true);
		primaryThread.executeUntil(entryPoint);

		// Allocate and fill remote memory for code and data
		size_t executeStart, remotePtr = allocateRemoteCodeAndData(info.hProcess, dllName, entryPoint + 5, executeStart);
		*cast(size_t*)(newCode.ptr + 1) = executeStart - (entryPoint + 5);

		// Load our DLL
		writeMemory(entryPoint, newCode, true);
		primaryThread.executeUntil(entryPoint + newCode.length - 2);

		// Free remote memory
		enforce(VirtualFreeEx(info.hProcess, cast(void*) remotePtr, 0, MEM_RELEASE));

		// Restore origin code
		writeMemory(entryPoint, originCode, true);

		// Restore origin memory protection
		enforce(changeMemoryProtection(entryPoint, originCode.length, oldProtection) == PAGE_EXECUTE_READWRITE);

		// Restore EIP and resume thread
		mainThread.changeContext(CONTEXT_CONTROL, (ref context) { context.Eip = entryPoint; });
		mainThread.resume();
	}

	int waitForExit()
	{
		WaitForSingleObject(info.hProcess, INFINITE);
		DWORD exitCode;
		enforce(GetExitCodeProcess(info.hProcess, &exitCode));
		// Note: If the process returned STILL_ACTIVE(259) we do not care
		return exitCode;
	}

	void closeHandles()
	{
		enforce(CloseHandle(info.hProcess));
		enforce(CloseHandle(info.hThread));
	}
}


private:

// TODO: throw on DLL loading failure
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

DWORD getEntryPoint(HANDLE hProcess)
{
	auto NtQueryInformationProcess = cast(NtQueryInformationProcess)
		enforce(GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationProcess"));

	void*[6] /* PROCESS_BASIC_INFORMATION */ pbi;
	ULONG returnLength;
	NtQueryInformationProcess(hProcess, 0 /* PROCESSINFOCLASS.ProcessBasicInformation */, &pbi, pbi.sizeof, &returnLength);
	assert(returnLength == pbi.sizeof);

	const(void)* imageBase;
	SIZE_T bytesRead;
	enforce(ReadProcessMemory(hProcess,
		pbi[1] /* PROCESS_BASIC_INFORMATION.PebBaseAddress */ + 8, // PEB.Reserved3[1] offset
		&imageBase, imageBase.sizeof, &bytesRead));
	enforce(bytesRead == imageBase.sizeof);

	LONG e_lfanew;
	enforce(ReadProcessMemory(hProcess,
		imageBase + 60 /* IMAGE_DOS_HEADER.e_lfanew offset*/,
		&e_lfanew, e_lfanew.sizeof, &bytesRead));
	enforce(bytesRead == e_lfanew.sizeof);
	const(void)* pNtHeaders = imageBase + e_lfanew;

	const(void)* entryPoint;
	enforce(ReadProcessMemory(hProcess,
		pNtHeaders + 24 /* OptionalHeader offset */ + 16 /* AddressOfEntryPoint offset */,
		&entryPoint, entryPoint.sizeof, &bytesRead));
	enforce(bytesRead == entryPoint.sizeof);

	return cast(DWORD) (imageBase + cast(size_t) entryPoint);
}

DWORD getEntryPoint(LPCWSTR file)
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
		enforce(GetProcAddress(LoadLibraryA("ntdll"), "RtlImageNtHeader"));

	const ntOptionalHeader = RtlImageNtHeader(pExe) + 24 /* OptionalHeader */;
	return *cast(size_t*) (ntOptionalHeader + 28 /* ImageBase */) +
		*cast(size_t*) (ntOptionalHeader + 16 /* AddressOfEntryPoint */);
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

public struct PROCESS_INFORMATION
{
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
}

extern(Windows) nothrow
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

	extern BOOL GetExitCodeProcess(
		HANDLE hProcess,
		LPDWORD lpExitCode
	);

	alias LONG NTSTATUS;

	alias NTSTATUS function(
		HANDLE ProcessHandle,
		int /* PROCESSINFOCLASS */ ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
	) NtQueryInformationProcess;
}
