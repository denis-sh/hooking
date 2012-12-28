/** NTDLL public and private WinAPI for TLS fixing

Searching for Ldrp* functions is based on Rainer Schuetze's algorithm
from druntime's $(D core.sys.windows.dll).

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.ntdll;

import core.sys.windows.windows;

public import hooking.windows.c.winternl;
import hooking.x86.utils;


extern(Windows) extern HANDLE GetProcessHeap() nothrow;
extern(Windows) HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) nothrow;

struct Ntdll {
static:
	extern(Windows) nothrow
	{
		alias void* function(PVOID HeapHandle, ULONG Flags, SIZE_T Size) FuncRtlAllocateHeap;
		alias BOOLEAN function(PVOID HeapHandle, ULONG Flags, PVOID HeapBase) FuncRtlFreeHeap;

		alias void function(RTL_BITMAP* BitMapHeader, PULONG BitMapBuffer, ULONG SizeOfBitMap) FuncRtlInitializeBitMap;
		alias ULONG function(RTL_BITMAP* BitMapHeader, ULONG NumberToFind, ULONG HintIndex) FuncRtlFindClearBitsAndSet;

		alias PVOID function (PVOID Base, BOOLEAN MappedAsImage, USHORT DirectoryEntry, PULONG Size)
			FuncRtlImageDirectoryEntryToData;

		alias NTSTATUS function(ULONG Flags, ULONG *State, ULONG *Cookie) FuncLdrLockLoaderLock;
		alias NTSTATUS function(ULONG Flags, ULONG Cookie) FuncLdrUnlockLoaderLock;

		alias .NtQuerySystemInformation FuncNtQuerySystemInformation;
		alias .NtQueryInformationThread FuncNtQueryInformationThread;
	}

	// RtlCheckBit is used only in `assert`
	ULONG RtlCheckBit(RTL_BITMAP* BitMapHeader, ULONG BitNumber) nothrow
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
		HMODULE hmodule;

		FuncRtlAllocateHeap  RtlAllocateHeap;
		FuncRtlFreeHeap      RtlFreeHeap;

		FuncRtlInitializeBitMap     RtlInitializeBitMap;
		FuncRtlFindClearBitsAndSet  RtlFindClearBitsAndSet;

		FuncRtlImageDirectoryEntryToData  RtlImageDirectoryEntryToData;

		FuncLdrLockLoaderLock LdrLockLoaderLock;
		FuncLdrUnlockLoaderLock LdrUnlockLoaderLock;

		FuncNtQuerySystemInformation NtQuerySystemInformation;
		FuncNtQueryInformationThread NtQueryInformationThread;

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

		hmodule = GetModuleHandleA("NTDLL");
		if(!hmodule)
			return false;

		bool loadFunc(alias func)() {
			func = cast(typeof(func)) GetProcAddress(hmodule, func.stringof.ptr);
			return !!func;
		}

		if(!loadFunc!RtlAllocateHeap() ||
		   !loadFunc!RtlFreeHeap() ||

		   !loadFunc!RtlInitializeBitMap() ||
		   !loadFunc!RtlFindClearBitsAndSet() ||

		   !loadFunc!RtlImageDirectoryEntryToData() ||

		   !loadFunc!LdrLockLoaderLock() ||
		   !loadFunc!LdrUnlockLoaderLock() ||

		   !loadFunc!NtQuerySystemInformation() ||
		   !loadFunc!NtQueryInformationThread())
			return false;

		void* pLdrInitializeThunk = GetProcAddress(hmodule, "LdrInitializeThunk");
		if(!pLdrInitializeThunk)
			return false;

		void* pLdrpInitialize = findCodeReference( pLdrInitializeThunk, 20, jmp_LdrpInitialize, true );
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
	private enum
		jmp_LdrpInitialize = x"33ED E9", // xor EBP, EBP; jmp _LdrpInitialize
		jmp__LdrpInitialize = x"5D E9", // pop EBP; jmp __LdrpInitialize
		jmp__LdrpInitialize_xp64 = x"5D 90 90 90 90 90", // pop EBP; nop; nop; nop; nop; nop;
		call_LdrpInitializeThread = x"FF7508 E8", // push [EBP+8]; call _LdrpInitializeThread
		call_LdrpAllocateTls = /*0F85 C300*/x"0000 E8", // jne $+0xC3; call _LdrpAllocateTls
		call_LdrpAllocateTls_svr03 = /*80*/x"65 FC 00 E8", // and byte ptr [EBP-0x4], 0; call _LdrpAllocateTls
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

struct IMAGE_TLS_DIRECTORY32 {
	DWORD   StartAddressOfRawData;
	DWORD   EndAddressOfRawData;
	DWORD   AddressOfIndex;             // PDWORD
	DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
	DWORD   SizeOfZeroFill;
	DWORD   Characteristics;
}

version(Win32) alias IMAGE_TLS_DIRECTORY32 IMAGE_TLS_DIRECTORY;
else static assert(0);
