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


/** This struct encapsulates process memory manipulation functionality.
*/
struct ProcessMemory
{
	/// Gets a $(D ProcessMemory) with associated with current processes.
	@property static ProcessMemory current()
	{ return ProcessMemory(GetCurrentProcess()); }

	unittest
	{
		auto current = ProcessMemory.current;
	}


	private HANDLE _processHandle;


	@disable this();
	@disable this(this);


	/// Construct a $(D ProcessMemory) from a $(D processHandle).
	this(HANDLE processHandle)
	out { assert(associated); }
	body
	{
		this._processHandle = processHandle;
	}

	/** Returns whether $(D this) is _associated with a process handle.
	It is asserted that no member functions are called for an unassociated
	$(D ProcessMemory) struct.

	Example:
	---
	assert(ProcessMemory.current.associated);
	assert(!ProcessMemory.init.associated);
	auto h = ProcessMemory.init.processHandle; // assert violation
	---
	*/
	@property bool associated() const @safe pure nothrow
	{ return !!_processHandle; }

	unittest
	{
		assert(ProcessMemory.current.associated);
		assert(!ProcessMemory.init.associated);
	}


	/// Gets the handle of the associated process. 
	@property HANDLE processHandle()
	in { assert(associated); }
	body { return _processHandle; }


	/** Set access protection of the specified memory region to $(D newProtection).
	Returns previous protection of the first page in the specified region.
	
	Preconditions:
	$(D newProtection) is a valid memory protection.
	*/
	DWORD changeProtection(RemoteAddress address, size_t size, DWORD newProtection)
	in
	{
		assert(associated);
		assert(isValidMemoryProtection(newProtection));
	}
	body
	{
		DWORD oldProtection;
		enforce(VirtualProtectEx(_processHandle, cast(LPVOID) address, size, newProtection, &oldProtection));
		return oldProtection;
	}


	/** Reads $(D buff.length) bytes of memory starting with $(D baseAddress) into $(D buff).

	Preconditions:
	$(D buff) isn't empty.

	Throws:
	$(D Exception) if requested memory region isn't available for reading.

	Example:
	---
	uint[1] buff;
	
	uint a = 7;
	current.read(cast(RemoteAddress) &a, buff);
	assert(buff[0] == 7);

	import std.exception: assertThrown;
	assertThrown(ProcessMemory.current.read(0, buff));
	---
	*/
	void read(RemoteAddress baseAddress, void[] buff)
	in
	{
		assert(associated);
		assert(buff.length);
	}
	body
	{
		enforce(ReadProcessMemory(_processHandle, cast(LPCVOID) baseAddress, buff.ptr, buff.length, null));
	}

	unittest
	{
		ubyte[1] buff;
		assertThrown(current.read(0, buff));
		assertThrown(current.read(size_t.max, buff));

		uint[2] a = [7, 8], b;
		current.read(cast(RemoteAddress) a.ptr, b);
		assert(b == [7, 8]);

		uint i;
		current.read(cast(RemoteAddress) a.ptr, (&i)[0 .. 1]);
		assert(i == 7);
	}


	/** Reads $(D T.sizeof) bytes of memory starting with $(D baseAddress)
	and returns it as $(D T).

	Throws:
	$(D Exception) if requested memory region isn't available for reading.

	Example:
	---
	uint a = 7;
	assert(current.get!uint(cast(RemoteAddress) &a) == 7);
	assert(current.get!(char[2])(cast(RemoteAddress) "ab".ptr) == "ab");

	import std.exception: assertThrown;
	assertThrown(current.get!ubyte(0));
	---
	*/
	T get(T)(RemoteAddress baseAddress)
	in { assert(associated); }
	body
	{
		T res = void;
		read(baseAddress, (cast(void*) &res)[0 .. T.sizeof]);
		return res;
	}

	unittest
	{
		assertThrown(current.get!ubyte(0));
		assertThrown(current.get!ubyte(size_t.max));

		uint a = 7;
		assert(current.get!uint(cast(RemoteAddress) &a) == 7);
		assert(current.get!(char[2])(cast(RemoteAddress) "ab".ptr) == "ab");
	}


	/** Writes $(D T.sizeof) bytes of memory starting with $(D baseAddress)
	and returns it as $(D T).

	Preconditions:
	$(D buff) isn't empty.

	Throws:
	$(D Exception) if requested memory region isn't available for writing.

	Example:
	---
	uint[3] a = [7, 8, 9];
	current.write(cast(RemoteAddress) &a[1], [10]);
	assert(a == [7, 10, 9]);

	import std.exception: assertThrown;
	assertThrown(current.write(0, [0]));
	---
	*/
	void write(RemoteAddress baseAddress, in void[] buff, bool flushInstructionCache = false)
	in
	{
		assert(associated);
		assert(buff.length);
	}
	body
	{
		enforce(WriteProcessMemory(_processHandle, cast(LPVOID) baseAddress, buff.ptr, buff.length, null));
		if(flushInstructionCache)
			enforce(FlushInstructionCache(_processHandle, cast(LPVOID) baseAddress, buff.length));
	}

	unittest
	{
		assertThrown(current.write(0, [0]));
		assertThrown(current.write(size_t.max, [0]));

		uint[3] a = [7, 8, 9];
		current.write(cast(RemoteAddress) &a[1], [10]);
		assert(a == [7, 10, 9]);
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
