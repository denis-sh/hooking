/** Functions for process memory manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.processmemory;

import core.sys.windows.windows;
import std.utf;
import std.exception;

import unstd.math: isPowerOf2;


static assert(size_t.sizeof == 4);

alias size_t RemoteAddress;

/** Returns whether $(D memory) is accosiated with a process handle.
It is asserted that no member functions are called for an unassociated
$(D ProcessMemory) struct.

Example:
---
assert(ProcessMemory.current.associated);
assert(!ProcessMemory.init.associated);
auto h = ProcessMemory.init.processHandle; // assert violation
---
*/
@property bool associated(in ProcessMemory memory) @safe pure nothrow
{ return !!memory._processHandle; }

unittest
{
	assert(ProcessMemory.current.associated);
	assert(!ProcessMemory.init.associated);
}


/** This struct encapsulates process memory manipulation functionality.
*/
struct ProcessMemory
{
	@property static ProcessMemory current()
	{ return ProcessMemory(GetCurrentProcess()); }


	private HANDLE _processHandle;

	invariant()
	{ assert(this.associated, "Attempting to use unassociated ProcessMemory struct"); }


	@disable this();

	this(HANDLE processHandle)
	{
		this._processHandle = processHandle;
	}


	@property HANDLE processHandle()
	{ return _processHandle; }

	/// Returns previous access protection of the first page in the specified region
	DWORD changeProtection(RemoteAddress address, size_t size, DWORD newProtection)
	in { assert(isValidMemoryProtection(newProtection)); }
	body
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


bool isValidMemoryProtection(DWORD protection) pure
{
	protection &= ~(PAGE_GUARD | PAGE_NOCACHE | 0x400 /*PAGE_WRITECOMBINE*/);
	enum allBits = PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
		PAGE_EXECUTE |PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
	static assert(allBits == 0xFF);
	return protection && !(protection & ~allBits) && isPowerOf2(protection);
}

unittest
{
	alias isValidMemoryProtection f;
	assert(f(PAGE_NOACCESS));
	assert(f(PAGE_EXECUTE_WRITECOPY));
	assert(f(PAGE_NOACCESS | PAGE_GUARD));
	assert(!f(PAGE_GUARD));
	assert(!f(PAGE_NOACCESS | PAGE_READONLY));
	assert(!f(PAGE_NOACCESS | PAGE_READONLY));
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
