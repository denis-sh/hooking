/** Functions for TLS fixing

Based on druntime's $(D core.sys.windows.dll) by Rainer Schuetze

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.dlltls;

import core.stdc.string: memcpy, memset;
import core.sys.windows.windows;
import core.sys.windows.threadaux;
import hooking.windows.pe;
import std.exception: enforce, enforceEx;
import std.string: xformat;

import unstd.math: roundUpToPowerOf2;

import tlsfixer.ntdll;


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

	numberOfTlsEntries = *Ntdll.pLdrpNumberOfTlsEntries;
	enforceEx!Error(modulesWithTls == numberOfTlsEntries, xformat(
		"Loaded module with TLS count = %s != %s = LdrpNumberOfTlsEntries",
		modulesWithTls, numberOfTlsEntries));

	enforceEx!Error(maxTlsIndex + 1 == numberOfTlsEntries, "maxTlsIndex + 1 != numberOfTlsEntries");


	// Fill TLS bitmap
	tlsArrayLength = numberOfTlsEntries;
	*Ntdll.pLdrpNumberOfTlsEntries = tlsArrayLength;//1024^^2 * 10
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

    if(!enumProcessThreadsNothrow(
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

    if(!enumProcessThreadsNothrow(
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

void onLdrShutdownThread() nothrow {
	foreach(ref array; leakedTlsArrays[0 .. leakedTlsArraysCount]) {
		freeProcessHeap(array.ptr);
		leakedBytes -= array.length;
		totalLeakedBytes -= array.length;
		array = null;
	}
	assert(!leakedBytes);
	leakedTlsArraysCount = 0;
}

private:

// Like `core.sys.windows.threadaux.enumProcessThreadsNothrow` but `nothrow` and with `in void* context`
bool enumProcessThreadsNothrow(bool function(uint id, in void* context) nothrow dg, in void* context) nothrow
{
	try return enumProcessThreads(cast(bool function(uint, void*) nothrow) dg, cast(void*) context);
	catch assert(0); // as the only thing that can throw in `enumProcessThreads` is `dg`
}

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
	size_t numberOfTlsEntries, tlsArrayLength;
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
		immutable newSize = roundUpToPowerOf2(idx + 1) / 8;
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

const(LdrpTlsListEntry*) addTlsListEntry(
	void* tlsstart, void* tlsend, void* tls_callbacks_a, int* tlsindex) nothrow
{
    // allocate new TlsList entry
    auto entry = cast(LdrpTlsListEntry*) allocateProcessHeap(LdrpTlsListEntry.sizeof);
    if(!entry) return null;

	*tlsindex = Ntdll.RtlFindClearBitsAndSet(&tlsBitmap, 1, 0);
	if(*tlsindex == -1)
	{
		assert(numberOfTlsEntries == tlsBitmap.SizeOfBitMap);
		useTlsIndex(*tlsindex = tlsBitmap.SizeOfBitMap);
	} else
		assert(numberOfTlsEntries < tlsBitmap.SizeOfBitMap);

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

	++numberOfTlsEntries;

    return entry;
}

void removeTlsListEntry(LdrpTlsListEntry* entry) nothrow
{
	assert(Ntdll.RtlCheckBit(&tlsBitmap, entry.tlsindex) == 1);
    Ntdll.RtlClearBit(&tlsBitmap, entry.tlsindex);

	// Remove it from the TlsList
    entry.next.prev = entry.prev;
    entry.prev.next = entry.next;

    --numberOfTlsEntries;

	// Free TlsList entry memory
	// FIXME: what is is was allocated by an other person and not freed?
	freeProcessHeap(entry);
}

__gshared size_t totalLeakedBytes;
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
		immutable newLength = roundUpToPowerOf2(tlsindex + 1);
		void** newArray = cast(void**) allocateProcessHeap(newLength * (void*).sizeof);
		if(!newArray) return false;

		if(tlsindex)
			memcpy(newArray, tlsArray, tlsArrayLength * (void*).sizeof);
		memset(newArray + tlsArrayLength, 0, (newLength - tlsArrayLength) * (void*).sizeof);

		// let the old array leak, in case a oncurrent thread is still relying on it
		leakedTlsArrays[leakedTlsArraysCount++] = tlsArray[0 .. tlsArrayLength];
		leakedBytes += tlsArrayLength * (void*).sizeof;
		totalLeakedBytes += tlsArrayLength * (void*).sizeof;

		tlsArrayLength = newLength;
		*Ntdll.pLdrpNumberOfTlsEntries = tlsArrayLength;
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
