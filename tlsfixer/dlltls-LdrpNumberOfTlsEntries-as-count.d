/**
 * This module provides OS specific helper function for DLL support
 *
 * Copyright: Copyright Digital Mars 2010 - 2010.
 * License:   <a href="http://www.boost.org/LICENSE_1_0.txt">Boost License 1.0</a>.
 * Authors:   Rainer Schuetze
 */

/*          Copyright Digital Mars 2010 - 2010.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

module core.sys.windows.dlltls;

import core.sys.windows.windows;
import core.sys.windows.threadaux_;
import stdd.windows.pe;
import std.exception;
import std.string;
import core.stdc.string: memcpy, memset;

void initializeDllTlsModule()
{
	__gshared bool initialized = false;
	if(initialized)
		return;
	scope(success) initialized = true;
	enforce(Ntdll.load());


	size_t maxTlsIndex = 0, modulesWithTls = 0;

	const(wchar)[][] curruptedModules = null; // Loaded modules with broken TLS

L:
	foreach(ldrMod; loadedModules)
    {
		const id = PEFile(ldrMod.BaseAddress, true).imageTlsDirectory;
        if(!id)
            continue; // No TLS directory

		++modulesWithTls;
		const tlsIndexPtr = cast(uint*) id.AddressOfIndex;
		if(*tlsIndexPtr)
		{
			if(maxTlsIndex < *tlsIndexPtr)
				maxTlsIndex = *tlsIndexPtr;
			continue; // TLS index is already set (it's initially 0)
		}

		const tlsHead = Ntdll.pLdrpTlsList;
		for(auto tlsEntry = cast() tlsHead.next; tlsEntry != tlsHead; tlsEntry = tlsEntry.next)
			if(tlsEntry.ptr_tlsindex == tlsIndexPtr)
				continue L; // The module is in LdrpTlsList

		const name = ldrMod.FullDllName;
		curruptedModules ~= name.Buffer[0 .. name.Length / 2];
    }

	enforceEx!Error(!curruptedModules, xformat(
		"There are already loaded module%s with broken TLS:\n%( %(%c%)\n%)",
		curruptedModules.length == 1 ? "" : "s", curruptedModules));

	enforceEx!Error(modulesWithTls == *Ntdll.pLdrpNumberOfTlsEntries, xformat(
		"Loaded module with TLS count = %s != %s = LdrpNumberOfTlsEntries",
		modulesWithTls, *Ntdll.pLdrpNumberOfTlsEntries));


	// Fill TLS bitmap
	tlsArrayLength = maxTlsIndex + 1;
	useTlsIndex(maxTlsIndex);
	foreach(ldrMod; loadedModules)
    {
        if(auto id = PEFile(ldrMod.BaseAddress, true).imageTlsDirectory)
			Ntdll.RtlSetBit(&tlsBitmap, *cast(uint*) id.AddressOfIndex);
	}
}

/* *****************************************************
* Fix implicit thread local storage for the case when a DLL is loaded
* dynamically after process initialization.
* The link time variables are passed to allow placing this function into
* an RTL DLL itself.
* The problem is described in Bugzilla 3342 and
* http://www.nynaeve.net/?p=187, to quote from the latter:
*
* "When a DLL using implicit TLS is loaded, because the loader doesn't process the TLS
*  directory, the _tls_index value is not initialized by the loader, nor is there space
*  allocated for module's TLS data in the ThreadLocalStoragePointer arrays of running
*  threads. The DLL continues to load, however, and things will appear to work... until the
*  first access to a __declspec(thread) variable occurs, that is."
*
* _tls_index is initialized by the compiler to 0, so we can use this as a test.
*/
bool setDllTls(HINSTANCE hInstance, void* tlsstart, void* tlsend, void* tls_callbacks_a, int* tlsindex) nothrow
{
    /* If the OS has allocated a TLS slot for us, we don't have to do anything
	* tls_index 0 means: the OS has not done anything, or it has allocated slot 0
	* Vista and later Windows systems should do this correctly and not need
	* this function.
	*/
    if(*tlsindex != 0)
        return true;

    LDR_MODULE* ldrMod = null;
    foreach(m; loadedModules) if(m.BaseAddress == hInstance)
	{ ldrMod = m; break; }
    if(!ldrMod) return false; // not in module list, bail out

    if(ldrMod.TlsIndex != 0)
        return true;  // the OS has already setup TLS

    const tlsEntry = addTlsListEntry(tlsstart, tlsend, tls_callbacks_a, tlsindex);
    if(!tlsEntry) return false;

    if(!enumProcessThreads(
		function (uint id, in void* context) nothrow
		{
			const tlsEntry = cast(LdrpTlsListEntry*) context;
			return addTlsData(getTEB(id), tlsEntry.tlsstart, tlsEntry.tlsend, tlsEntry.tlsindex);
		}, tlsEntry))
        return false;

    ldrMod.TlsIndex = -1;  // flag TLS usage (not the index itself)
    //ldrMod.LoadCount = -1; // prevent unloading of the DLL,
	// since XP does not keep track of used TLS entries
    return true;
}

bool freeDllTls(HINSTANCE hInstance, int* tlsindex) nothrow
{
	LdrpTlsListEntry* tlsEntry = null;
    foreach(e; tlsEntries) if(e.tlsindex == *tlsindex)
	{ tlsEntry = e; break; }
    if(!tlsEntry) return false; // not in TLS entries list, bail out

	assert(tlsEntry.ptr_tlsindex == tlsindex);

    if(!enumProcessThreads(
		function (uint id, in void* context) nothrow
		{
			const tlsEntry = cast(LdrpTlsListEntry*) context;
			removeTlsData(getTEB(id), tlsEntry.tlsindex);
			return true;
		}, tlsEntry))
        return false;

	removeTlsListEntry(tlsEntry);

	return true;
}

private:

void** getPEB() nothrow
{
	asm { naked; mov EAX, FS:[0x30]; ret; }
}

static struct ListEntryRange(T)
{
	const LIST_ENTRY*  root;
	LIST_ENTRY* entry;

nothrow:
	this(T* root)
	{
		auto t = cast(LIST_ENTRY*) root;
		this.root = t;
		entry = t.Flink;
	}

	@property empty() const
	{ return entry == root; }

	void popFront()
	in { assert(!empty); }
	body { entry = entry.Flink; }

	@property front() const
	{ return cast(T*) entry; }
}

@property loadedModules() nothrow
{
	const peb = getPEB();
	auto ldrData = cast(PEB_LDR_DATA*) peb[3];
    auto root = cast(LDR_MODULE*) &ldrData.InLoadOrderModuleList;
	return ListEntryRange!LDR_MODULE(root);
}


@property tlsEntries() nothrow
{
	return ListEntryRange!LdrpTlsListEntry(Ntdll.pLdrpTlsList);
}

__gshared {
	RTL_BITMAP tlsBitmap;
	size_t tlsArrayLength;
}

void useTlsIndex(size_t idx) nothrow
{
	__gshared size_t[8] staticStorage;
	enum staticSize = 8 * staticStorage.sizeof;

	if(!tlsBitmap.SizeOfBitMap && idx < staticSize)
	{
		Ntdll.RtlInitializeBitMap(&tlsBitmap, staticStorage.ptr, staticSize);
	}
	else if(idx >= tlsBitmap.SizeOfBitMap)
	{
		immutable newSize = toPowerOf2(idx + 1) / 8;
		auto newBuff = cast(ULONG*) allocateProcessHeap(newSize);
		if(tlsBitmap.Buffer)
		{
			memcpy(newBuff, tlsBitmap.Buffer, tlsBitmap.SizeOfBitMap / 8);
			if(tlsBitmap.Buffer != staticStorage.ptr)
				freeProcessHeap(tlsBitmap.Buffer);
		}
		Ntdll.RtlInitializeBitMap(&tlsBitmap, newBuff, newSize);
	}
	Ntdll.RtlSetBit(&tlsBitmap, idx);
}

// don't let symbols leak into other modules TODO why?
const(LdrpTlsListEntry*) addTlsListEntry(
	void* tlsstart, void* tlsend, void* tls_callbacks_a, int* tlsindex) nothrow
{
    // allocate new TlsList entry
    auto entry = cast(LdrpTlsListEntry*) allocateProcessHeap(LdrpTlsListEntry.sizeof);
    if(!entry) return null;

	*tlsindex = Ntdll.RtlFindClearBitsAndSet(&tlsBitmap, 1, 0);
	if(*tlsindex == -1)
	{
		assert(*Ntdll.pLdrpNumberOfTlsEntries == tlsBitmap.SizeOfBitMap);
		useTlsIndex(*tlsindex = tlsBitmap.SizeOfBitMap);
	} else
		assert(*Ntdll.pLdrpNumberOfTlsEntries < tlsBitmap.SizeOfBitMap);

    // fill entry
    entry.tlsstart = tlsstart;
    entry.tlsend = tlsend;
    entry.ptr_tlsindex = tlsindex;
    entry.callbacks = tls_callbacks_a;
    entry.zerofill = null;
    entry.tlsindex = *tlsindex;

    // and add it to the end of TlsList
    entry.next = Ntdll.pLdrpTlsList;
    entry.prev = Ntdll.pLdrpTlsList.prev;
    Ntdll.pLdrpTlsList.prev.next = entry;
    Ntdll.pLdrpTlsList.prev = entry;

	// On thread start TLS is allocated for each element of
	// pLdrpTlsList. pLdrpNumberOfTlsEntries is only checked
	// not been 0.
    ++*Ntdll.pLdrpNumberOfTlsEntries;

    return entry;
}

void removeTlsListEntry(LdrpTlsListEntry* entry) nothrow
{
	assert(Ntdll.RtlCheckBit(&tlsBitmap, entry.tlsindex) == 1);
    Ntdll.RtlClearBit(&tlsBitmap, entry.tlsindex);

	// Remove it from the TlsList
    entry.next.prev = entry.prev;
    entry.prev.next = entry.next;

    --*Ntdll.pLdrpNumberOfTlsEntries;

	// Free TlsList entry memory
	// FIXME: what is is was allocated by an other person and not freed?
	freeProcessHeap(entry);
}

size_t leakedTlsArraysCount, leakedBytes;
void*[][32] leakedTlsArrays;

// Create a copy of the TLS data section and reallocate TLS array if needed
bool addTlsData(void** teb, in void* tlsstart, in void* tlsend, in int tlsindex) nothrow
{
    immutable sz = tlsend - tlsstart;
    void* tlsdata = cast(void*) allocateProcessHeap(sz);
    if(!tlsdata) return false;

    // No relocations! not even self-relocations. Windows does not do them.
    memcpy(tlsdata, tlsstart, sz);

	auto tlsArray = cast(void**) teb[11];
	assert(!(tlsindex && !tlsArray));
	if(tlsindex >= tlsArrayLength)
	{
		// Create copy of TLS array
		immutable newLength = toPowerOf2(tlsindex + 1);
		void** newArray = cast(void**) allocateProcessHeap(newLength * (void*).sizeof);
		if(!newArray) return false;

		if(tlsindex)
			memcpy(newArray, tlsArray, tlsArrayLength * (void*).sizeof);
		memset(newArray + tlsArrayLength, 0, (newLength - tlsArrayLength) * (void*).sizeof);

		// let the old array leak, in case a oncurrent thread is still relying on it
		leakedTlsArrays[leakedTlsArraysCount++] = tlsArray[0 .. tlsArrayLength];
		leakedBytes += tlsArrayLength * (void*).sizeof;

		tlsArrayLength = newLength;
		teb[11] = tlsArray = newArray;
	}
	assert(!tlsArray[tlsindex]);
	tlsArray[tlsindex] = tlsdata;
    return true;
}

void removeTlsData(void** teb, in int tlsindex) nothrow
in { assert(tlsindex < tlsArrayLength); }
body
{
	auto tlsArray = cast(void**) teb[11];
	freeProcessHeap(tlsArray[tlsindex]);
	tlsArray[tlsindex] = null;
}

void* allocateProcessHeap(size_t size) nothrow
in { assert(size); }
out(res) { assert(res); }
body
{
	// Adding 0xC0000 to the tag is obviously a flag also usesd by the nt-loader,
	// could be the result of HEAP_MAKE_TAG_FLAGS(0, HEAP_NO_SERIALIZE | HEAP_GROWABLE)
	// but this is not documented in the msdn entry for RtlAlloateHeap
	return Ntdll.RtlAllocateHeap(GetProcessHeap(), *Ntdll.pNtdllBaseTag | 0xC0000, size);
}

void freeProcessHeap(void* heapBase) nothrow
in { assert(heapBase); }
body
{
	bool res = Ntdll.RtlFreeHeap(GetProcessHeap(), 0, heapBase);
	assert(res);
}

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

		try
		{
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
		catch { return false; }
	}

	// find a code sequence and return the address after the sequence
	void* findCodeSequence( void* adr, int len, ref ubyte[] pattern )
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
	void* findCodeReference( void* adr, int len, ref ubyte[] pattern, bool relative )
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

//module lge.utils.math;

import core.bitop: bsr;

/// Returnes $(D true) iff $(D n) is a power of 2
bool isPowerOf2(uint n) pure nothrow
in { assert(n > 0); }
body { return !((n - 1) & n); }

unittest {
	assert(isPowerOf2(1));
	assert(isPowerOf2(2));
	assert(!isPowerOf2(3));
	assert(isPowerOf2(4));
	assert(!isPowerOf2(5));
}

/// Returnes smallest power of 2 which >= $(D n)
int toPowerOf2(uint n) pure nothrow
in { assert(n > 0); }
body {
	return 1 << (bsr(n) + !isPowerOf2(n));
}

unittest {
	assert(toPowerOf2(1) == 1);
	assert(toPowerOf2(2) == 2);
	assert(toPowerOf2(3) == 4);
	assert(toPowerOf2(4) == 4);
	assert(toPowerOf2(5) == 8);
}