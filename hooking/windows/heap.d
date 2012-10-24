/** Functions for heap manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.heap;

import core.sys.windows.windows;
import std.exception;


@property bool associated(in Heap heap) @safe pure nothrow
{ return !!heap._handle; }


/// Returns default heap of the calling process.
@property Heap processHeap()
{ return Heap(GetProcessHeap()); }


/// This struct encapsulates heap manipulation functionality.
struct Heap
{
	private HANDLE _handle;

	invariant()
	{ assert(this.associated, "Attempting to use unassociated Heap struct"); }

	@property HANDLE handle()
	{ return _handle; }

	T[] alloc(T = void)(size_t count, DWORD flags = 0)
	{
		return enforce(cast(T*) HeapAlloc(_handle, flags, countToBytes(T.sizeof, count)))[0 .. count];
	}

	void realloc(T)(ref T[] array, size_t newCount, DWORD flags = 0)
	{
		array = array ?
			enforce(cast(T*) HeapReAlloc(_handle, flags, array.ptr, countToBytes(T.sizeof, newCount)))[0 .. newCount]
			: alloc!T(newCount);
	}

	void destructiveRealloc(T)(ref T[] array, size_t newCount)
	{
		immutable size_t newBytes = countToBytes(T.sizeof, newCount);
		if(!array)
			array = alloc!T(newCount);
		else if(HeapReAlloc(_handle, HEAP_REALLOC_IN_PLACE_ONLY, array.ptr, newBytes))
			array = array.ptr[0 .. newCount];
		else
		{
			auto res = enforce(cast(T*) HeapAlloc(_handle, 0, newBytes))[0 .. newCount];
			scope(failure) free(res.ptr);
			free(array.ptr);
			array = res;
		}
	}

	void free(void* p, DWORD flags = 0)
	{
		BOOL res = HeapFree(_handle, flags, p);
		// Workaround bug mentioned in "Community Additions" section of
		// http://msdn.microsoft.com/en-us/library/windows/desktop/aa366701(v=vs.85).aspx
		if(cast(ubyte) GetVersion() < 6) // Not Windows Vista or later
			res = cast(ubyte) res;
		enforce(res);
	}
}

private size_t countToBytes(size_t elementSize, size_t count)
{
	immutable size_t bytes = count * elementSize;
	enforce(bytes / elementSize == count);
	return bytes;
}


// WinAPI
// --------------------------------------------------
enum : DWORD
{
	HEAP_NO_SERIALIZE              = 0x00000001,
	HEAP_GROWABLE                  = 0x00000002,
	HEAP_GENERATE_EXCEPTIONS       = 0x00000004,
	HEAP_ZERO_MEMORY               = 0x00000008,
	HEAP_REALLOC_IN_PLACE_ONLY     = 0x00000010,
	HEAP_TAIL_CHECKING_ENABLED     = 0x00000020,
	HEAP_FREE_CHECKING_ENABLED     = 0x00000040,
	HEAP_DISABLE_COALESCE_ON_FREE  = 0x00000080,
	HEAP_CREATE_ALIGN_16           = 0x00010000,
	HEAP_CREATE_ENABLE_TRACING     = 0x00020000,
	HEAP_CREATE_ENABLE_EXECUTE     = 0x00040000,
	HEAP_MAXIMUM_TAG               = 0x0FFF,
	HEAP_PSEUDO_TAG_FLAG           = 0x8000,
	HEAP_TAG_SHIFT                 = 18,
}

DWORD HEAP_MAKE_TAG_FLAGS(DWORD TagBase, DWORD Tag) @safe pure nothrow
{
    return cast(DWORD)(TagBase + (Tag << HEAP_TAG_SHIFT));
}


extern(Windows) nothrow
{
	extern HANDLE GetProcessHeap();
	extern PVOID HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
	extern PVOID HeapReAlloc (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
	extern BOOL HeapFree (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
}
