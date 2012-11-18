/** Functions for process manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.process;

import core.sys.windows.windows;
import core.time;
import std.utf;
import std.exception;
import std.algorithm;
import std.string;

import hooking.windows.c.winternl;
import hooking.windows.heap;
import hooking.windows.thread;
import hooking.windows.processmemory;
import hooking.windows.processstartinfo;


version(unittest) Process testLaunch()
{
	return Process(ProcessStartInfo("notepad", null, true, true));
}


/** This struct encapsulates process hooking functionality.
*/
struct Process
{
	/** Returns a $(D Process) with pseudo handle of current processes retrieved by
	$(WEB msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx, GetCurrentProcess)
	that is valid only in the context of current processes.
	*/
	@property static Process currentLocal()
	{ return Process(GetCurrentProcess(), PROCESS_ALL_ACCESS, true); }

	unittest
	{
		auto local = Process.currentLocal;
		local.closeHandles();
	}


	/** Returns a $(D Process) with "real" handle of current processes
	that is valid in the context of other processes.
	*/
	static Process getCurrentGlobal()
	{ return Process(GetCurrentProcessId(), PROCESS_ALL_ACCESS, false); }

	unittest
	{
		auto global = Process.getCurrentGlobal();
		global.closeHandles();
	}


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
		DWORD _handleAccess;
		DWORD _processId;
		Thread _primaryThread;
	}
	

	/** Construct a $(D Process) from a $(D processId).
	If $(D tryUsePseudoHandle) is $(D true) and $(D processId)
	is current process id then pseudo handle with $(D PROCESS_ALL_ACCESS)
	access will be used.
	Otherwise if $(D desiredAccess) is non-zero then a process handle
	will be opened with requested access.
	Otherwise no handle is opened.
	*/
	this(DWORD processId, DWORD desiredAccess, bool tryUsePseudoHandle)
	out { assert(associated); }
	body
	{
		if(tryUsePseudoHandle && processId == GetCurrentProcessId())
		{
			_handle = GetCurrentProcess();
			_handleAccess = PROCESS_ALL_ACCESS;
		}
		else if(desiredAccess)
		{
			_handle = enforce(OpenProcess(desiredAccess, TRUE /* bInheritHandle */, processId));
			_handleAccess = desiredAccess;
		}
		_processId = processId;
	}


	/** Construct a $(D Process) from a $(D processHandle).
	$(D processHandle) access obtained when it was opened
	should be passed as $(D handleAccess) parameter.
	If $(D remainPseudoHandle) is $(D false) and $(D processHandle)
	is pseudo handle of current process then "real" handle with
	access from $(D handleAccess) will be opened instead.
	If $(D remainPseudoHandle) is $(D true) and $(D processHandle)
	is pseudo handle then $(D handleAccess) will be set to $(D PROCESS_ALL_ACCESS).

	$(D processId) will not be set iff resulting $(D handleAccess)
	doesn't include $(D PROCESS_QUERY_INFORMATION) or $(D PROCESS_QUERY_LIMITED_INFORMATION).
	In this case calling $(D closeHandles) will result in unassociation of this struct.
	*/
	this(HANDLE processHandle, DWORD handleAccess, bool remainPseudoHandle)
	out { assert(associated); }
	body
	{
		immutable bool isPseudoHandle = processHandle == GetCurrentProcess();
		if(!remainPseudoHandle && isPseudoHandle)
			this = Process(GetCurrentProcessId(), handleAccess, false);
		else
		{
			_handle = processHandle;
			_handleAccess = isPseudoHandle ? PROCESS_ALL_ACCESS : handleAccess;
			if(_handleAccess & (PROCESS_QUERY_INFORMATION  | PROCESS_QUERY_LIMITED_INFORMATION))
				_processId = enforce(GetProcessId(processHandle));
		}
	}


	/** Launch a new process.
	
	$(D handleAccess) will be set to $(D PROCESS_ALL_ACCESS).
	$(D primaryThread) will be set.

	Preconditions:
	$(D startInfo) is associated.

	Example:
	---
	// With executable file searching:
	Process(ProcessStartInfo("notepad", true)).closeHandles();

	// Without executable file searching:
	import std.process;
	immutable path = environment["windir"] ~ `\system32\notepad.exe`;
	Process(ProcessStartInfo(path, null)).closeHandles(); // using file & arguments
	Process(ProcessStartInfo('"' ~ path ~ '"')).closeHandles(); // using command line
	---
	*/
	this(in ProcessStartInfo startInfo)
	out { assert(associated); }
	body
	{
		DWORD creationFlags = 0;
		if(startInfo.suspended)
			creationFlags |= CREATE_SUSPENDED;
		if(startInfo.createNewConsole)
			creationFlags |= CREATE_NEW_CONSOLE;
		STARTUPINFOW startupInfo = { STARTUPINFOW.sizeof };
		PROCESS_INFORMATION info;
		enforce(CreateProcessW(
			startInfo.searchForFile ? null : toUTF16z(startInfo.file),
			toUTF16(startInfo.commandLine ~ '\0').dup.ptr,
			null, null, TRUE /* bInheritHandles */, creationFlags, null, null, &startupInfo, &info));
		_handle = info.hProcess;
		_handleAccess = PROCESS_ALL_ACCESS;
		_processId = info.dwProcessId;
		_primaryThread._handle = info.hThread;
		_primaryThread._threadId = info.dwThreadId;
	}

	unittest
	{
		auto p = Process(ProcessStartInfo("cmd /c echo Hello!", true, true, true));
		assert(p.handleAccess == PROCESS_ALL_ACCESS);
		assert(p.primaryThread.threadId);
		scope(exit) p.closeHandles();
		p.terminate();
	}

	unittest
	{
		import std.process;
		immutable windir = environment["windir"], pathNoExt = windir ~ `\system32\cmd`;
		assert(!windir.canFind(' '), xformat("Can't test with %%windir%%='%s'", windir));

		assertThrown!Exception(Process(ProcessStartInfo("cmd"    , false, true)));
		assertThrown!Exception(Process(ProcessStartInfo("cmd.exe", false, true)));
		assertThrown!Exception(Process(ProcessStartInfo(pathNoExt, false, true)));

		void assertLaunchs(string commandLine, bool search)
		{
			auto p = Process(ProcessStartInfo(commandLine, search, true));
			scope(exit) p.closeHandles();
			p.terminate();
		}

		assertLaunchs(pathNoExt ~ ".exe", false);
		assertLaunchs('"' ~ pathNoExt ~ `.exe"`, false);
		assertLaunchs(pathNoExt ~ ".exe 1", false);
		assertLaunchs('"' ~ pathNoExt ~ `.exe" 1`, false);
		assertLaunchs(pathNoExt, true);
		assertLaunchs("cmd", true);
	}


	/** Returns whether $(D process) is _associated with a process.
	It is asserted that no member functions are called for an unassociated
	$(D Process) struct.

	Example:
	---
	assert(Process.currentLocal.associated);
	assert(!Process.init.associated);
	auto h = Process.init.handle; // assert violation
	---

	Bugs:
	The check is implemented as $(D Process) invariant and disabled because of $(BUGZILLA 7892).
	*/
	@property bool associated() const @safe pure nothrow
	{ return _handle || _processId; }

	unittest
	{
		assert(Process.currentLocal.associated);
		assert(!Process.init.associated);
	}


	/// Gets the native _handle.
	@property HANDLE handle()
	in { assert(associated); }
	body { return _handle; }


	/// Gets access to the $(D handle).
	@property DWORD handleAccess() const
	in { assert(associated); }
	body { return _handleAccess; }


	/// Gets the process identifier.
	@property DWORD processId() const
	in { assert(associated); }
	body { return _processId; }


	/** Gets the primary thread.

	Preconditions:
	The process is created with a constructor launching an executable file.
	*/
	@property Thread primaryThread()
	in 
	{
		assert(associated);
		assert(_primaryThread._handle);
	}
	body { return _primaryThread; }


	/// Gets associated $(D ProcessMemory) instance.
	@property ProcessMemory memory()
	in { assert(associated); }
	body { return ProcessMemory(handle); }


	/** Initializes internal Windows stuff required for WinAPI
	functions like $(D EnumProcessModules).

	When a process is created such stuff isn't initialized unless
	some process code is executed.

	Preconditions:
	The process is created suspended and not started yet or its primary thread is paused
	before initialization is finished (before module entry point is reached
	in current implementation).
	$(RED Preconditions violation results in undefined behavior.)

	Example:
	---
	import std.process;
	auto p = Process(environment["windir"] ~ `\system32\notepad.exe`, null, true);
	scope(exit) p.closeHandles();
	scope(exit) p.terminate();

	HMODULE[256] buff;
	DWORD needed;

	// The call will fail because internal Windows stuff isn't initialized yet:
	assert(!EnumProcessModules(p.handle, buff.ptr, buff.sizeof, &needed));

	p.initializeWindowsStuff();

	assert(EnumProcessModules(p.handle, buff.ptr, buff.sizeof, &needed));
	---
	*/
	void initializeWindowsStuff()
	in { assert(associated); }
	body
	{
		RemoteAddress entryPoint = getEntryPoint(_handle);

		enum loopCode = x"EB FE"; // JMP $-2

		// Change memory protection (before reading because it can be PAGE_EXECUTE)
		DWORD oldProtection = memory.changeProtection(entryPoint, loopCode.length, PAGE_EXECUTE_READWRITE);
		enforce(oldProtection & 0xF0); // Expect some PAGE_EXECUTE_* constant

		ubyte[loopCode.length] originCode;
		memory.read(entryPoint, originCode);         // Save origin code
		memory.write(entryPoint, loopCode, true);    // Write new loop code (and flush instruction cache)
		primaryThread.executeUntil(entryPoint);      // Let Windows initialize its stuff
		memory.write(entryPoint, originCode, true);  // Restore origin code

		// Restore origin memory protection
		enforce(memory.changeProtection(entryPoint, loopCode.length, oldProtection) == PAGE_EXECUTE_READWRITE);
	}

	unittest
	{
		auto p = testLaunch();
		scope(exit) p.terminate(), p.closeHandles();

		HMODULE[256] buff;
		DWORD needed;

		// The call will fail because internal Windows stuff isn't initialized yet:
		assert(!EnumProcessModules(p.handle, buff.ptr, buff.sizeof, &needed));

		p.initializeWindowsStuff();

		assert(EnumProcessModules(p.handle, buff.ptr, buff.sizeof, &needed));
	}


	/** Gets loaded modules.

	Preconditions:
	Initialized internal Windows stuff.
	No DLL are loaded/unloaded during function call.
	$(RED Preconditions violation results in undefined behavior.)

	Example:
	---
	import std.process: environment;
	auto p = Process(environment["windir"] ~ `\system32\notepad.exe`, null, true);
	scope(exit) p.closeHandles();
	scope(exit) p.terminate();

	p.initializeWindowsStuff();
	auto modules = p.getModules();
	---
	*/
	HMODULE[] getModules()
	in { assert(associated); }
	body
	{
		auto buff = helperEnumProcessModules(_handle);
		scope(exit) processHeap.free(buff.ptr);
		return buff.dup;
	}

	unittest
	{
		auto p = testLaunch();
		scope(exit) p.terminate(), p.closeHandles();

		p.initializeWindowsStuff();
		assert(p.getModules().length > 1);
	}


	/// Returns thread identifiers of all running threads in the process.
	DWORD[] getThreadIds()
	in { assert(associated); }
	body
	{
		auto buff = helperNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemProcessInformation, 0x20000);
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
	}

	unittest
	{
		auto p = testLaunch();
		scope(exit) p.terminate(), p.closeHandles();

		assert(p.getThreadIds().length == 1);
	}


	/** Loads module into the process.

	Preconditions:
	Initialized internal Windows stuff.
	$(RED Preconditions violation results in undefined behavior.)
	*/
	void loadDll(string dllName)
	in { assert(associated); }
	body
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

	/** Terminates the process and set its exit code with $(D exitCode).

	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms686714(v=vs.85).aspx,
	TerminateProcess).
	*/
	void terminate(uint exitCode = -1)
	in { assert(associated); }
	body
	{
		enforce(TerminateProcess(_handle, exitCode));
	}

	/// Waits for the process to exit and returns exit code.
	int waitForExit()
	in { assert(associated); }
	body
	{
		enforce(WaitForSingleObject(_handle, INFINITE) == WAIT_OBJECT_0);
		DWORD exitCode;
		enforce(GetExitCodeProcess(_handle, &exitCode));
		// Note: If the process returned STILL_ACTIVE(259) we do not care
		return exitCode;
	}

	unittest
	{
		auto p = testLaunch();
		scope(exit) p.closeHandles();

		p.terminate(-3);
		assert(p.waitForExit() == -3);
	}


	/** Waits the specified $(D duration) for the process to exit
	and returns wheter it exited. If it does exited, set $(D exitCode)
	with the process exit code.

	Bugs:
	If total milliseconds in duration >= $(D uint.max) (more than 49 days)
	it will wait infinite time (i.e. equals to $(D waitForExit())).
	*/ 
	bool waitForExit(Duration duration, out uint exitCode)
	in { assert(associated); }
	body
	{
		immutable ulong msecs = duration.total!"msecs"();
		static assert(INFINITE == uint.max);
		if(msecs >= uint.max)
		{
			exitCode = waitForExit();
			return true;
		}

		immutable DWORD waitRes = WaitForSingleObject(_handle, cast(uint) msecs);
		if(waitRes == WAIT_TIMEOUT)
			return false;
		enforce(waitRes == WAIT_OBJECT_0);

		enforce(GetExitCodeProcess(_handle, &exitCode));
		// Note: If the process returned STILL_ACTIVE(259) we do not care
		return true;
	}

	/// ditto
	bool waitForExit(Duration duration)
	in { assert(associated); }
	body
	{
		uint exitCode;
		return waitForExit(duration, exitCode);
	}

	unittest
	{
		auto p = testLaunch();
		scope(exit) p.closeHandles();
		uint exitCode;

		assert(!p.waitForExit(dur!"msecs"(1), exitCode) && exitCode == 0);

		p.terminate(-2);
		while(!p.waitForExit(dur!"msecs"(0), exitCode)) { }
		assert(exitCode == -2);
		assert(p.waitForExit(dur!"msecs"( 1), exitCode) && exitCode == -2);
		assert(p.waitForExit(dur!"days" (50), exitCode) && exitCode == -2);
	}
}


/** Closes $(D process) handles if any.
$(D process) may be unassociated.
*/
void closeHandles(ref Process process)
{
	if(process._handle && process._handle != GetCurrentProcess())
	{
		enforce(CloseHandle(process._handle));
		process._handle = null;
	}
	process._primaryThread.closeHandle();
}

unittest
{
	auto unassociated = Process.init;
	unassociated.closeHandles();

	auto local = Process.currentLocal;
	local.closeHandles();

	auto global = Process.getCurrentGlobal();
	global.closeHandles();
}


enum : DWORD
{
	PROCESS_TERMINATE                  = 0x0001,
	PROCESS_CREATE_THREAD              = 0x0002,
	PROCESS_SET_SESSIONID              = 0x0004,
	PROCESS_VM_OPERATION               = 0x0008,
	PROCESS_VM_READ                    = 0x0010,
	PROCESS_VM_WRITE                   = 0x0020,
	PROCESS_DUP_HANDLE                 = 0x0040,
	PROCESS_CREATE_PROCESS             = 0x0080,
	PROCESS_SET_QUOTA                  = 0x0100,
	PROCESS_SET_INFORMATION            = 0x0200,
	PROCESS_QUERY_INFORMATION          = 0x0400,
	PROCESS_SUSPEND_RESUME             = 0x0800,
	PROCESS_QUERY_LIMITED_INFORMATION  = 0x1000,

	PROCESS_ALL_ACCESS        = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF
};


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
	enforce(NtQueryInformationProcess(hProcess, 0 /* PROCESSINFOCLASS.ProcessBasicInformation */, &pbi, pbi.sizeof, &returnLength) >= 0);
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


// WinAPI helpers
// --------------------------------------------------

HMODULE[] helperEnumProcessModules(HANDLE hProcess)
{
	HMODULE[] buff;
	DWORD needed = 0;
	do
	{
		processHeap.destructiveRealloc!HMODULE(buff, max(needed + 0x100, buff.length * 2));
		scope(failure) processHeap.free(buff.ptr);
		enforce(EnumProcessModules(hProcess, buff.ptr, buff.length * HMODULE.sizeof, &needed));
		assert(needed % HMODULE.sizeof == 0);
		needed /= HMODULE.sizeof;
	}
	while(needed > buff.length);
	return buff[0 .. needed];
}

void[] helperNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, size_t initialBufferSize)
{
	auto NtQuerySystemInformation = cast(NtQuerySystemInformation)
		enforce(GetProcAddress(LoadLibraryA("ntdll"), "NtQuerySystemInformation"));

	auto buff = processHeap.alloc(initialBufferSize);
	for(;;)
	{
		DWORD needed = -1;
		NTSTATUS res = NtQuerySystemInformation(SystemInformationClass,
			buff.ptr, buff.length, &needed);
		if(res != STATUS_INFO_LENGTH_MISMATCH)
		{
			scope(failure) processHeap.free(buff.ptr);
			enforce(res >= 0);
			return buff[0 .. needed];
		}
		// Possible integer overflow will not lead to memory corruption.
		// And Windows definitely will not support such amount of processes/threads.
		processHeap.destructiveRealloc(buff, max(needed + 0x2000, buff.length * 2));
	}
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

	pragma(lib, "psapi.lib");
	extern BOOL EnumProcesses(DWORD *pProcessIds, DWORD cb, DWORD *pBytesReturned);

	extern BOOL EnumProcessModules(
		HANDLE hProcess,
		HMODULE *lphModule,
		DWORD cb,
		LPDWORD lpcbNeeded
	);

	extern BOOL TerminateProcess(
		HANDLE hProcess,
		UINT uExitCode
	);
}
