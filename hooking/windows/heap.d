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

extern(Windows) nothrow
{
	extern HANDLE GetProcessHeap();
	extern PVOID HeapAlloc(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
	extern BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
}
