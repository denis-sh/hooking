/** Functions for process manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.process;

import core.sys.windows.windows;
import std.utf;
import std.exception;
import std.algorithm: max;

import hooking.windows.heap;
import hooking.windows.thread;
import hooking.windows.processmemory;


/** This struct encapsulates process hooking functionality.
*/
struct Process
{
	/** Returns a $(D Process) with pseudo handle of current processes retrieved by
	$(WEB msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx, GetCurrentProcess)
	that is valid only in the context of current processes.
	*/
	@property static Process currentLocal()
	{ return Process(GetCurrentProcess(), true); }


	/** Returns a $(D Process) with "real" handle of current processes
	that is valid in the context of other processes.
	*/
	static Process getCurrentGlobal()
	{ return Process(GetCurrentProcessId(), false); }


	/** Returns process identifiers of all running processes.

	Example:
	---
	import std.algorithm;

	bool isProcessRunning(int processId)
	{
		return Process.getRunningIds().canFind(processId);
	}
	---
	*/
	@property static DWORD[] getRunningIds()
	{
		DWORD bytesReturned = -1;
		auto buff = processHeap.alloc!DWORD(0x100);
		for(;;)
		{
			immutable buffBytes = buff.length * DWORD.sizeof;
			{
				scope(failure) processHeap.free(buff.ptr);
				enforce(EnumProcesses(buff.ptr, buffBytes, &bytesReturned));
			}
			assert(bytesReturned % DWORD.sizeof == 0);
			if(bytesReturned < buffBytes)
				break;
			processHeap.free(buff.ptr);
			// As DWORD.sizeof (4) >= 2, no integer overflow here:
			buff = processHeap.alloc!DWORD(buff.length * 2);
		}
		auto res = buff[0 .. bytesReturned / DWORD.sizeof].dup;
		processHeap.free(buff.ptr);
		return res;
	}


	private
	{
		HANDLE _handle;
		DWORD _processId;
		Thread _primaryThread;
	}
	

	version(none) // invariant disabled because of @@@BUG7892@@@
	invariant()
	{ assert(_processId || _handle, "Attempting to use unassociated Process struct"); }


	/** Construct a $(D Process) from a $(D processId).
	If $(D tryUsePseudoHandle) is $(D true) and $(D processId)
	is current process id then pseudo handle will be used.
	*/
	this(DWORD processId, bool tryUsePseudoHandle)
	{
		_handle = tryUsePseudoHandle && processId == GetCurrentProcessId() ?
			GetCurrentProcess() :
			enforce(OpenProcess(0X001F0FFF /* PROCESS_ALL_ACCESS */, TRUE /* bInheritHandle */, processId));
		_processId = processId;
	}


	/** Construct a $(D Process) from a $(D processHandle).
	If $(D remainPseudoHandle) is $(D false) and $(D processHandle)
	is pseudo handle of current process then "real" handle
	will be used instead.
	*/
	this(HANDLE processHandle, bool remainPseudoHandle)
	{
		if(!remainPseudoHandle && processHandle == GetCurrentProcess())
			this = Process(GetCurrentProcessId(), false);
		else
		{
			_handle = processHandle;
			_processId = GetProcessId(processHandle);
		}
	}

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
		PROCESS_INFORMATION info;
		enforce(CreateProcessW(toUTF16z(file), arguments ? toUTF16(arguments ~ '\0').dup.ptr : null,
			null, null, TRUE /* bInheritHandles */, creationFlags, null, null, &startupInfo, &info));
		_handle = info.hProcess;
		_processId = info.dwProcessId;
		_primaryThread = Thread(info.hThread, info.dwThreadId);
	}


	@property HANDLE handle()
	{ return _handle; }

	@property DWORD processId() const
	{ return _processId; }

	@property Thread primaryThread()
	in { assert(_primaryThread._handle); }
	body { return _primaryThread; }

	@property ProcessMemory memory()
	{ return ProcessMemory(handle); }

	void initializeWindowsStuff()
	{
		RemoteAddress entryPoint = getEntryPoint(_handle);

		enum loopCode = x"EB FE"; // JMP $-2

		// Change memory protection (before reading because it can be PAGE_EXECUTE)
		DWORD oldProtection = memory.changeProtection(entryPoint, loopCode.length, PAGE_EXECUTE_READWRITE);
		enforce(oldProtection & 0xF0); // Expect some PAGE_EXECUTE_* constant

		ubyte[loopCode.length] originCode;
		memory.read(entryPoint, originCode);         // Save origin code
		memory.write(entryPoint, loopCode, true);    // Write new loop code (and flush instruction cache)
		primaryThread.executeUntil(entryPoint);        // Let Windows initialize its stuff
		memory.write(entryPoint, originCode, true);  // Restore origin code

		// Restore origin memory protection
		enforce(memory.changeProtection(entryPoint, loopCode.length, oldProtection) == PAGE_EXECUTE_READWRITE);
	}

	@property DWORD[] getThreadIds()
	{
		auto NtQuerySystemInformation = cast(NtQuerySystemInformation)
			enforce(GetProcAddress(LoadLibraryA("ntdll"), "NtQuerySystemInformation"));

		auto buff = processHeap.alloc(0x20000);
		for(;;)
		{
			DWORD bytesReturned = -1;
			NTSTATUS res = NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemProcessInformation,
				buff.ptr, buff.length, &bytesReturned);
			if(res != STATUS_INFO_LENGTH_MISMATCH)
			{
				scope(failure) processHeap.free(buff.ptr);
				enforce(res >= 0);
				assert(bytesReturned <= buff.length);
				buff.length = bytesReturned;
				break;
			}
			processHeap.free(buff.ptr);
			// Possible integer overflow will not lead to memory corruption.
			// And Windows definitely will not support such amount of processes/threads.
			buff = processHeap.alloc(max(bytesReturned + 0x2000, buff.length * 2));
		}
		scope(exit) processHeap.free(buff.ptr);

		size_t offset = 0;
		for(;;)
		{
			auto sysProcessInfo = cast(SYSTEM_PROCESS_INFORMATION*) (buff.ptr + offset);

			if(cast(DWORD) sysProcessInfo.UniqueProcessId == processId)
			{
				auto threadIds = new DWORD[sysProcessInfo.NumberOfThreads];
				auto sysThreadInfo = cast(SYSTEM_THREAD_INFORMATION*) (sysProcessInfo + 1);
				foreach(ref threadId; threadIds)
				{
					assert(cast(DWORD) sysThreadInfo.ClientId.UniqueProcess == processId);
					threadId = cast(DWORD) sysThreadInfo.ClientId.UniqueThread;
					++sysThreadInfo;
				}
				return threadIds;
			}

			enforce(sysProcessInfo.NextEntryOffset, "Process has exited.");
			offset += sysProcessInfo.NextEntryOffset;
		}

		assert(0);
	}

	void loadDll(string dllName)
	{
		// Suspend thread and get its EIP
		primaryThread.suspend();
		RemoteAddress address = primaryThread.getContext(CONTEXT_CONTROL).Eip;

		ubyte[5 + 2] newCode = cast(const(ubyte)[]) x"E9 00000000 EB FE"; // JMP rel32; JMP $-2;

		// Change memory protection (before reading because it can be PAGE_EXECUTE)
		DWORD oldProtection = memory.changeProtection(address, newCode.length, PAGE_EXECUTE_READWRITE);
		enforce(oldProtection & 0xF0); // Expect some PAGE_EXECUTE_* constant

		ubyte[newCode.length] originCode;
		memory.read(address, originCode);         // Save origin code

		// Allocate and fill remote memory for code and data
		size_t executeStart, remotePtr = allocateRemoteCodeAndData(this, dllName, address + 5, executeStart);
		*cast(size_t*)(newCode.ptr + 1) = executeStart - (address + 5);

		// Load our DLL
		memory.write(address, newCode, true);
		primaryThread.executeUntil(address + newCode.length - 2);

		// Free remote memory
		enforce(VirtualFreeEx(_handle, cast(void*) remotePtr, 0, MEM_RELEASE));

		// Restore origin code
		memory.write(address, originCode, true);

		// Restore origin memory protection
		enforce(memory.changeProtection(address, originCode.length, oldProtection) == PAGE_EXECUTE_READWRITE);

		// Restore EIP and resume thread
		primaryThread.changeContext(CONTEXT_CONTROL, (ref context) { context.Eip = address; });
		primaryThread.resume();
	}

	int waitForExit()
	{
		WaitForSingleObject(_handle, INFINITE);
		DWORD exitCode;
		enforce(GetExitCodeProcess(_handle, &exitCode));
		// Note: If the process returned STILL_ACTIVE(259) we do not care
		return exitCode;
	}

	void closeHandles()
	{
		if(_handle != GetCurrentProcess())
		{
			enforce(CloseHandle(_handle));
			_handle = null;
		}
		if(_primaryThread._handle)
			_primaryThread.closeHandle();
	}
}


private:

// TODO: throw on DLL loading failure
size_t allocateRemoteCodeAndData(Process process, string dllName, size_t jmpAddress, out size_t executeStart)
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
	immutable remotePtr = cast(RemoteAddress) enforce
		(VirtualAllocEx(process.handle, null, buff.length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

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
	process.memory.write(remotePtr, buff, true);

	return remotePtr;
}


// WinAPI helpers
// --------------------------------------------------

RemoteAddress getEntryPoint(HANDLE hProcess)
{
	auto NtQueryInformationProcess = cast(NtQueryInformationProcess)
		enforce(GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationProcess"));

	RemoteAddress[6] /* PROCESS_BASIC_INFORMATION */ pbi;
	ULONG returnLength;
	NtQueryInformationProcess(hProcess, 0 /* PROCESSINFOCLASS.ProcessBasicInformation */, &pbi, pbi.sizeof, &returnLength);
	assert(returnLength == pbi.sizeof);

	auto mem = ProcessMemory(hProcess);
	RemoteAddress imageBase = mem.get!RemoteAddress(
		pbi[1] /* PROCESS_BASIC_INFORMATION.PebBaseAddress */ + 8, // PEB.Reserved3[1] offset
	);

	LONG e_lfanew = mem.get!LONG(
		imageBase + 60 /* IMAGE_DOS_HEADER.e_lfanew offset*/
	);
	RemoteAddress pNtHeaders = imageBase + e_lfanew;

	RemoteAddress entryPoint = mem.get!RemoteAddress(
		pNtHeaders + 24 /* OptionalHeader offset */ + 16 /* AddressOfEntryPoint offset */
	);

	return imageBase + cast(size_t) entryPoint;
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
	extern DWORD GetProcessId(HANDLE Process);

	extern HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

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

	extern BOOL GetExitCodeProcess(
		HANDLE hProcess,
		LPDWORD lpExitCode
	);

	alias LONG NTSTATUS;

	enum : NTSTATUS
	{
		STATUS_INFO_LENGTH_MISMATCH = 0xc0000004,
	}

	alias NTSTATUS function(
		HANDLE ProcessHandle,
		int /* PROCESSINFOCLASS */ ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength
	) NtQueryInformationProcess;

	// From winternl.h
	enum SYSTEM_INFORMATION_CLASS
	{
		SystemProcessInformation = 5,
	}

	// From winternl.h
	alias NTSTATUS function(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	) NtQuerySystemInformation;

	pragma(lib, "psapi.lib");
	extern BOOL EnumProcesses(DWORD *pProcessIds, DWORD cb, DWORD *pBytesReturned);

	// From http://msdn.microsoft.com/en-us/library/gg750724(prot.20).aspx
	// NumberOfThreads from http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/System%20Information/Structures/SYSTEM_PROCESS_INFORMATION.html
	struct SYSTEM_PROCESS_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		BYTE Reserved1[52 - ULONG.sizeof];
		PVOID Reserved2[3];
		HANDLE UniqueProcessId;
		PVOID Reserved3;
		ULONG HandleCount;
		BYTE Reserved4[4];
		PVOID Reserved5[11];
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER Reserved6[6];
	}

	// From http://msdn.microsoft.com/en-us/library/gg750647(prot.20).aspx
	struct CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	}

	// From http://msdn.microsoft.com/en-us/library/gg750724(prot.20).aspx
	struct SYSTEM_THREAD_INFORMATION
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		LONG Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		ULONG WaitReason;
	}
}
