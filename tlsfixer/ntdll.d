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
		void* fn = GetProcAddress( hnd, "LdrInitializeThunk" );
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
	inout(void)* findCodeSequence(inout(void)* startAddress, in size_t len, in string pattern) nothrow
	{
		if(!startAddress)
			return null;

		auto code = cast(inout(ubyte)*) startAddress;
		foreach(p; 0 .. len)
			if(code[p .. p + pattern.length] == pattern)
				return code + p + pattern.length;
		return null;
	}

	// find a code sequence and return the (relative) address that follows
	inout(void)* findCodeReference(inout(void)* startAddress, in size_t len, in string pattern, in bool relative) nothrow
	{
		if(auto p = cast(inout(ubyte)*) findCodeSequence(startAddress, len, pattern))
			return relative ? (p + 4 + *cast(int*) p) :
				(*cast(inout(void)**) p);
		return null;
	}

	/*
	crawl through ntdll to find function _LdrpAllocateTls@0 and references
	 to _LdrpNumberOfTlsEntries, _NtdllBaseTag and _LdrpTlsList
	LdrInitializeThunk
	-> _LdrpInitialize@12
	-> _LdrpInitializeThread@4
	-> _LdrpAllocateTls@0
	-> je chunk
	    _LdrpNumberOfTlsEntries - number of entries in TlsList
	    _NtdllBaseTag           - tag used for RtlAllocateHeap
	    _LdrpTlsList            - root of the double linked list with TlsList entries
	*/
	enum
		jmp_LdrpInitialize = x"33ED E9", // xor EBP, EBP; jmp _LdrpInitialize
		jmp__LdrpInitialize = x"5D E9", // pop EBP; jmp __LdrpInitialize
		jmp__LdrpInitialize_xp64 = x"5D 90 90 90 90 90", // pop EBP; nop; nop; nop; nop; nop;
		call_LdrpInitializeThread = x"FF7508 E8", // push [EBP+8]; call _LdrpInitializeThread
		call_LdrpAllocateTls = x"0000 E8", // jne 0xc3; call _LdrpAllocateTls
		call_LdrpAllocateTls_svr03 = x"65 fc 00 E8", // and [EBP+0xfc], 0; call _LdrpAllocateTls
		jne_LdrpAllocateTls = x"0F85", // jne body_LdrpAllocateTls
		mov_LdrpNumberOfTlsEntries = x"8B0D", // mov ECX, _LdrpNumberOfTlsEntries
		mov_NtdllBaseTag = x"51 8B0D", // push ECX; mov ECX, _NtdllBaseTag
		mov_NtdllBaseTag_srv03 = x"50 A1", // push EAX; mov EAX, _NtdllBaseTag
		mov_LdrpTlsList = x"8B3D"; // mov EDI, _LdrpTlsList
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
