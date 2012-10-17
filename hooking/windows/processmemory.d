/** Functions for process memory manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.processmemory;

import core.sys.windows.windows;
import std.utf;
import std.exception;


static assert(size_t.sizeof == 4);

alias size_t RemoteAddress;

/** This struct encapsulates process memory manipulation functionality.
*/
struct ProcessMemory
{
	private HANDLE _processHandle;


	@disable this();

	this(HANDLE processHandle)
	{
		this._processHandle = processHandle;
	}


	@property HANDLE processHandle()
	{ return _processHandle; }

	/// Returns previous access protection of the first page in the specified region
	DWORD changeProtection(RemoteAddress address, size_t size, DWORD newProtection)
	{
		DWORD oldProtection;
		enforce(VirtualProtectEx(_processHandle, cast(LPVOID) address, size, newProtection, &oldProtection));
		return oldProtection;
	}

	void read(RemoteAddress baseAddress, void[] buff)
	{
		enforce(ReadProcessMemory(_processHandle, cast(LPCVOID) baseAddress, buff.ptr, buff.length, null));
	}

	T get(T)(RemoteAddress baseAddress)
	{
		T res = void;
		read(baseAddress, (cast(void*) &res)[0 .. T.sizeof]);
		return res;
	}

	void write(RemoteAddress baseAddress, in void[] buff, bool flushInstructionCache = false)
	{
		enforce(WriteProcessMemory(_processHandle, cast(LPVOID) baseAddress, buff.ptr, buff.length, null));
		if(flushInstructionCache)
			enforce(FlushInstructionCache(_processHandle, cast(LPVOID) baseAddress, buff.length));
	}
}


private:

// WinAPI
// --------------------------------------------------

extern(Windows) nothrow
{
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
