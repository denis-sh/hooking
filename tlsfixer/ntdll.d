/** NTDLL public and private WinAPI for TLS fixing

Searching for Ldrp* functions is based on Rainer Schuetze's algorithm
from druntime's $(D core.sys.windows.dll).

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.ntdll;

import core.sys.windows.windows;


extern(Windows) extern HANDLE GetProcessHeap() nothrow;

struct Ntdll {
static:
	extern(Windows) nothrow
	{
		alias void* function(PVOID HeapHandle, ULONG Flags, SIZE_T Size) FuncRtlAllocateHeap;
		alias BOOLEAN function(PVOID HeapHandle, ULONG Flags, PVOID HeapBase) FuncRtlFreeHeap;

		alias void function(RTL_BITMAP* BitMapHeader, PULONG BitMapBuffer, ULONG SizeOfBitMap) FuncRtlInitializeBitMap;
		alias ULONG function(RTL_BITMAP* BitMapHeader, ULONG NumberToFind, ULONG HintIndex) FuncRtlFindClearBitsAndSet;
	}

	debug ULONG RtlCheckBit(RTL_BITMAP* BitMapHeader, ULONG BitNumber) nothrow
	in { assert(BitNumber < BitMapHeader.SizeOfBitMap); }
	body
	{
		return (BitMapHeader.Buffer[BitNumber >> 5] >> (BitNumber & 31)) & 1;
	}

	void RtlSetBit(RTL_BITMAP* BitMapHeader, ULONG BitNumber) nothrow
	in { assert(BitNumber < BitMapHeader.SizeOfBitMap); }
	body
	{
		BitMapHeader.Buffer[BitNumber >> 5] |= (1 << (BitNumber & 31));
	}

	void RtlClearBit(RTL_BITMAP* BitMapHeader, ULONG BitNumber) nothrow
	in { assert(BitNumber < BitMapHeader.SizeOfBitMap); }
	body 
	{
		BitMapHeader.Buffer[BitNumber >> 5] &= ~(1 << (BitNumber & 31));
	}


	__gshared {
		FuncRtlAllocateHeap  RtlAllocateHeap;
		FuncRtlFreeHeap      RtlFreeHeap;

		FuncRtlInitializeBitMap     RtlInitializeBitMap;
		FuncRtlFindClearBitsAndSet  RtlFindClearBitsAndSet;

		int* pNtdllBaseTag;
		
		// On thread start TLS is allocated for each element of
		// pLdrpTlsList. pLdrpNumberOfTlsEntries is only used
		// as TLS array length.
		int* pLdrpNumberOfTlsEntries;
		
		LdrpTlsListEntry* pLdrpTlsList;
	}


	bool load() nothrow
	{
		__gshared bool loaded = false;
		if(loaded)
			return true;

		HMODULE hnd = GetModuleHandleA( "NTDLL" );
		assert( hnd, "cannot get module handle for ntdll" );
		ubyte* fn = cast(ubyte*) GetProcAddress( hnd, "LdrInitializeThunk" );
		assert( fn, "cannot find LdrInitializeThunk in ntdll" );

		bool loadFunc(alias func)() {
			func = cast(typeof(func)) GetProcAddress(hnd, func.stringof.ptr);
			return !!func;
		}

		if(!loadFunc!RtlAllocateHeap() ||
		   !loadFunc!RtlFreeHeap() ||

		   !loadFunc!RtlInitializeBitMap() ||
		   !loadFunc!RtlFindClearBitsAndSet())
			return false;

		void* pLdrpInitialize = findCodeReference( fn, 20, jmp_LdrpInitialize, true );
		void* p_LdrpInitialize = findCodeReference( pLdrpInitialize, 40, jmp__LdrpInitialize, true );
		if( !p_LdrpInitialize )
			p_LdrpInitialize = findCodeSequence( pLdrpInitialize, 40, jmp__LdrpInitialize_xp64 );
		void* pLdrpInitializeThread = findCodeReference( p_LdrpInitialize, 200, call_LdrpInitializeThread, true );
		void* pLdrpAllocateTls = findCodeReference( pLdrpInitializeThread, 40, call_LdrpAllocateTls, true );
		if(!pLdrpAllocateTls)
			pLdrpAllocateTls = findCodeReference( pLdrpInitializeThread, 100, call_LdrpAllocateTls_svr03, true );
		void* pBodyAllocateTls = findCodeReference( pLdrpAllocateTls, 40, jne_LdrpAllocateTls, true );

		pLdrpNumberOfTlsEntries = cast(int*) findCodeReference( pBodyAllocateTls, 60, mov_LdrpNumberOfTlsEntries, false );
		pNtdllBaseTag = cast(int*) findCodeReference( pBodyAllocateTls, 30, mov_NtdllBaseTag, false );
		if(!pNtdllBaseTag)
			pNtdllBaseTag = cast(int*) findCodeReference( pBodyAllocateTls, 30, mov_NtdllBaseTag_srv03, false );
		pLdrpTlsList = cast(LdrpTlsListEntry*)findCodeReference( pBodyAllocateTls, 80, mov_LdrpTlsList, false );

		if( !pLdrpNumberOfTlsEntries || !pNtdllBaseTag || !pLdrpTlsList )
			return false;

		loaded = true;
		return true;
	}

private:
	// find a code sequence and return the address after the sequence
	void* findCodeSequence( void* adr, int len, ref ubyte[] pattern ) nothrow
	{
		if( !adr )
			return null;

		ubyte* code = cast(ubyte*) adr;
		for( int p = 0; p < len; p++ )
		{
			if( code[ p .. p + pattern.length ] == pattern[ 0 .. $ ] )
			{
				ubyte* padr = code + p + pattern.length;
				return padr;
			}
		}
		return null;
	}

	// find a code sequence and return the (relative) address that follows
	void* findCodeReference( void* adr, int len, ref ubyte[] pattern, bool relative ) nothrow
	{
		if( !adr )
			return null;

		ubyte* padr = cast(ubyte*) findCodeSequence( adr, len, pattern );
		if( padr )
		{
			if( relative )
				return padr + 4 + *cast(int*) padr;
			return *cast(void**) padr;
		}
		return null;
	}

	// crawl through ntdll to find function _LdrpAllocateTls@0 and references
	//  to _LdrpNumberOfTlsEntries, _NtdllBaseTag and _LdrpTlsList
	// LdrInitializeThunk
	// -> _LdrpInitialize@12
	// -> _LdrpInitializeThread@4
	// -> _LdrpAllocateTls@0
	// -> je chunk
	//     _LdrpNumberOfTlsEntries - number of entries in TlsList
	//     _NtdllBaseTag           - tag used for RtlAllocateHeap
	//     _LdrpTlsList            - root of the double linked list with TlsList entries
	__gshared {
		ubyte[] jmp_LdrpInitialize = [ 0x33, 0xED, 0xE9 ]; // xor ebp,ebp; jmp _LdrpInitialize
		ubyte[] jmp__LdrpInitialize = [ 0x5D, 0xE9 ]; // pop ebp; jmp __LdrpInitialize
		ubyte[] jmp__LdrpInitialize_xp64 = [ 0x5D, 0x90, 0x90, 0x90, 0x90, 0x90 ]; // pop ebp; nop; nop; nop; nop; nop;
		ubyte[] call_LdrpInitializeThread = [ 0xFF, 0x75, 0x08, 0xE8 ]; // push [ebp+8]; call _LdrpInitializeThread
		ubyte[] call_LdrpAllocateTls = [ 0x00, 0x00, 0xE8 ]; // jne 0xc3; call _LdrpAllocateTls
		ubyte[] call_LdrpAllocateTls_svr03 = [ 0x65, 0xfc, 0x00, 0xE8 ]; // and [ebp+fc], 0; call _LdrpAllocateTls
		ubyte[] jne_LdrpAllocateTls = [ 0x0f, 0x85 ]; // jne body_LdrpAllocateTls
		ubyte[] mov_LdrpNumberOfTlsEntries = [ 0x8B, 0x0D ]; // mov ecx, _LdrpNumberOfTlsEntries
		ubyte[] mov_NtdllBaseTag = [ 0x51, 0x8B, 0x0D ]; // push ecx; mov ecx, _NtdllBaseTag
		ubyte[] mov_NtdllBaseTag_srv03 = [ 0x50, 0xA1 ]; // push eax; mov eax, _NtdllBaseTag
		ubyte[] mov_LdrpTlsList = [ 0x8B, 0x3D ]; // mov edi, _LdrpTlsList
	}
}

// WinAPI structs
// --------------------------------------------------

struct RTL_BITMAP
{
	ULONG SizeOfBitMap;
	ULONG* Buffer;
}

struct LdrpTlsListEntry
{
	LdrpTlsListEntry* next;
	LdrpTlsListEntry* prev;
	void* tlsstart;
	void* tlsend;
	void* ptr_tlsindex;
	void* callbacks;
	void* zerofill;
	int   tlsindex;
}


alias bool BOOLEAN;

struct UNICODE_STRING
{
	short Length;
	short MaximumLength;
	wchar* Buffer;
}

// the following structures can be found here: http://undocumented.ntinternals.net/
struct LDR_MODULE
{
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
	PVOID           BaseAddress;
	PVOID           EntryPoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	ULONG           Flags;
	SHORT           LoadCount;
	SHORT           TlsIndex;
	LIST_ENTRY      HashTableEntry;
	ULONG           TimeDateStamp;
}

struct PEB_LDR_DATA
{
	ULONG           Length;
	BOOLEAN         Initialized;
	PVOID           SsHandle;
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
}
