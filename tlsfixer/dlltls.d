/** Functions for TLS fixing

Based on druntime's $(D core.sys.windows.dll) by Rainer Schuetze

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.dlltls;

import core.stdc.stdlib: free;
import core.stdc.string: memcpy, memset;
import core.sys.windows.windows;
debug(dlltls) import core.stdc.stdio: fputs, fprintf, puts, printf;

import unstd.math: roundUpToPowerOf2;

import tlsfixer.ntdll;
import tlsfixer.winutils;


const(IMAGE_TLS_DIRECTORY)* getImageTlsDirectory(void* moduleBase) nothrow
in { assert(!(cast(size_t) moduleBase & 0xFFFF)); }
body
{
	ULONG size;
	void* res = Ntdll.RtlImageDirectoryEntryToData(moduleBase, true, 9 /* IMAGE_DIRECTORY_ENTRY_TLS */, &size);
	assert(!res || size == IMAGE_TLS_DIRECTORY.sizeof);
	return cast(typeof(return)) res;
}


void initializeDllTlsModule() nothrow
{
	__gshared bool initialized = false;
	if(initialized)
		return;

	enforceErr(Ntdll.load());


	size_t maxTlsIndex = 0, modulesWithTls = 0;

	size_t curruptedModulesCount = 0; // Loaded modules with broken TLS count

L:
	foreach(ldrMod; loadedModules)
	{
		const id = getImageTlsDirectory(ldrMod.BaseAddress);
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
		debug(dlltls)
		{
			if(!curruptedModulesCount)
				fputs("There are already loaded modules with broken TLS:\n", stderr);
			import core.stdc.wchar_: fwprintf;
			fwprintf(stderr, " %.*s\n", name.Length / 2, name.Buffer);
		}
		++curruptedModulesCount;
	}

	enforceErr(!curruptedModulesCount, "There are already loaded modules with broken TLS");

	numberOfTlsEntries = *Ntdll.pLdrpNumberOfTlsEntries;
	debug(dlltls)
	{
		if(modulesWithTls != numberOfTlsEntries)
			fprintf(stderr,
				"Loaded module with TLS count = %zu != %zu = LdrpNumberOfTlsEntries\n",
				modulesWithTls, numberOfTlsEntries);
	}

	enforceErr(modulesWithTls == numberOfTlsEntries,
		"Loaded module with TLS count != LdrpNumberOfTlsEntries");

	enforceErr(maxTlsIndex + 1 == numberOfTlsEntries, "maxTlsIndex + 1 != numberOfTlsEntries");


	// Fill TLS bitmap
	tlsArrayLength = numberOfTlsEntries;
	useTlsIndex(maxTlsIndex);
	foreach(ldrMod; loadedModules)
	{
		if(auto id = getImageTlsDirectory(ldrMod.BaseAddress))
			Ntdll.RtlSetBit(&tlsBitmap, *cast(uint*) id.AddressOfIndex);
	}

	leakedTlsIndex = TlsAlloc();
	enforceErr(leakedTlsIndex != 0xFFFFFFFF /* TLS_OUT_OF_INDEXES */);

	initialized = true;
}

/**
Fix implicit thread local storage for the case when a DLL is loaded
dynamically after process initialization.
The link time variables are passed to allow placing this function into
an RTL DLL itself.
The problem is described in Bugzilla 3342 and
http://www.nynaeve.net/?p=187, to quote from the latter:

"When a DLL using implicit TLS is loaded, because the loader doesn't process the TLS
 directory, the _tls_index value is not initialized by the loader, nor is there space
 allocated for module's TLS data in the ThreadLocalStoragePointer arrays of running
 threads. The DLL continues to load, however, and things will appear to work... until the
 first access to a __declspec(thread) variable occurs, that is."

_tls_index is initialized by the compiler to 0, so we can use this as a test.
*/
bool setDllTls(HINSTANCE hInstance, void* tlsstart, void* tlsend, void* tls_callbacks_a, int* tlsindex) nothrow
{
	if(*tlsindex != 0)
		return false; // the OS has already setup TLS, bail out

	LDR_MODULE* ldrMod = null;
	foreach(m; loadedModules) if(m.BaseAddress == hInstance)
	{ ldrMod = m; break; }
	if(!ldrMod) return false; // not in module list, bail out

	if(ldrMod.TlsIndex != 0)
		return false; // the OS has already setup TLS, bail out

	const tlsEntry = addTlsListEntry(tlsstart, tlsend, tls_callbacks_a, tlsindex);
	if(!tlsEntry) return false;

	auto threadIds = getCurrentProcessThreadIds();
	if(!threadIds)
		return false;
	debug(dlltls) printf("Setting TLS to %zu thread(s)\n", threadIds.length);
	foreach(threadId; threadIds)
		if(!addTlsData(getTEB(threadId), tlsEntry.tlsstart, tlsEntry.tlsend, tlsEntry.tlsindex))
			return free(threadIds.ptr), false;
	free(threadIds.ptr);

	ldrMod.TlsIndex = -1;  // flag TLS usage (not the index itself)
	// Note: we can set `ldrMod.LoadCount = -1` to prevent unloading of the DLL
	return true;
}

bool freeDllTls(HINSTANCE hInstance, int* tlsindex) nothrow
{
	LdrpTlsListEntry* tlsEntry = null;
	foreach(e; tlsEntries) if(e.tlsindex == *tlsindex)
	{ tlsEntry = e; break; }
	if(!tlsEntry) return false; // not in TLS entries list, bail out

	assert(tlsEntry.ptr_tlsindex == tlsindex);

	auto threadIds = getCurrentProcessThreadIds();
	if(!threadIds)
		return false;
	debug(dlltls) printf("Freeing TLS from %zu thread(s)\n", threadIds.length);
	foreach(threadId; threadIds)
		removeTlsData(getTEB(threadId), tlsEntry.tlsindex);
	free(threadIds.ptr);

	removeTlsListEntry(tlsEntry);

	return true;
}

void onLdrShutdownThread() nothrow
{
	debug(dlltls) puts("On LdrShutdownThread");
	auto leakedTls = cast(LeakedTls*) TlsGetValue(leakedTlsIndex);
	enforceErr(GetLastError() == ERROR_SUCCESS); // TlsGetValue always call SetLastError
	if(!leakedTls)
		return;

	debug(dlltls) printf("Freeing %zu leaked TLS arrays (%zu elements:", leakedTls.arraysCount, leakedTls.bytes / (void*).sizeof);
	foreach(ref array; leakedTls.arrays[0 .. leakedTls.arraysCount])
	{
		debug(dlltls) printf(" %zu", array.length);
		freeProcessHeap(array.ptr);
		leakedTls.bytes -= array.length;
		totalLeakedBytes -= array.length;
		array = null;
	}
	debug(dlltls) puts(")");
	assert(!leakedTls.bytes);
	freeProcessHeap(leakedTls);
	debug enforceErr(TlsSetValue(leakedTlsIndex, cast(void*) -1));
}

private:

void** getPEB() nothrow
{
	asm { naked; mov EAX, FS:[0x30]; ret; }
}


// Get the thread environment block (TEB) of the thread with the given identifier
void** getTEB(uint threadId) nothrow
{
	HANDLE handle = enforceErr(OpenThread(0x40 /* THREAD_QUERY_INFORMATION */, FALSE, threadId));

	THREAD_BASIC_INFORMATION tbi;
	ULONG returnLength;
	NTSTATUS res = Ntdll.NtQueryInformationThread(handle, 0 /* THREADINFOCLASS.ThreadBasicInformation */, &tbi, tbi.sizeof, &returnLength);

	enforceErr(CloseHandle(handle));

	enforceErr(res >= 0);
	assert(returnLength == tbi.sizeof);
	return cast(void**) tbi.TebBaseAddress;
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

__gshared
{
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
	auto entry = cast(LdrpTlsListEntry*) allocateProcessHeapAsLoader(LdrpTlsListEntry.sizeof);
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
	freeProcessHeap(entry);
}

struct LeakedTls
{
	size_t arraysCount, bytes;
	void*[][32] arrays;
}

__gshared
{
	size_t totalLeakedBytes;
	DWORD leakedTlsIndex;
}

// Create a copy of the TLS data section and reallocate TLS array if needed
bool addTlsData(void** teb, in void* tlsstart, in void* tlsend, in int tlsindex) nothrow
{
	immutable sz = tlsend - tlsstart;
	void* tlsdata = cast(void*) allocateProcessHeapAsLoader(sz);
	if(!tlsdata) return false;

	// No relocations! Not even self-relocations. Windows does not do them.
	memcpy(tlsdata, tlsstart, sz);

	auto tlsArray = cast(void**) teb[11];
	assert(!(tlsindex && !tlsArray));
	if(tlsindex >= tlsArrayLength)
	{
		// Create copy of TLS array
		immutable uint newLength = roundUpToPowerOf2(tlsindex + 1);
		debug(dlltls) printf("Allocating new TLS array of %u elements\n", newLength);
		void** newArray = cast(void**) allocateProcessHeapAsLoader(newLength * (void*).sizeof);
		if(!newArray) return false;

		if(tlsindex)
			memcpy(newArray, tlsArray, tlsArrayLength * (void*).sizeof);
		memset(newArray + tlsArrayLength, 0, (newLength - tlsArrayLength) * (void*).sizeof);

		auto leakedTls = cast(LeakedTls*) TlsGetValue(leakedTlsIndex);
		enforceErr(GetLastError() == ERROR_SUCCESS); // TlsGetValue always call SetLastError
		assert(leakedTls != cast(void*) -1);
		if(!leakedTls)
		{
			leakedTls = cast(LeakedTls*) allocateProcessHeap(LeakedTls.sizeof, 8 /* HEAP_ZERO_MEMORY */);
			enforceErr(TlsSetValue(leakedTlsIndex, leakedTls));
		}

		// let the old array leak, in case a oncurrent thread is still relying on it
		leakedTls.arrays[leakedTls.arraysCount++] = tlsArray[0 .. tlsArrayLength];
		leakedTls.bytes += tlsArrayLength * (void*).sizeof;
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

void* allocateProcessHeapAsLoader(size_t size) nothrow
{
	// Adding 0xC0000 to the tag is obviously a flag also usesd by the nt-loader,
	// could be the result of HEAP_MAKE_TAG_FLAGS(0, HEAP_NO_SERIALIZE | HEAP_GROWABLE)
	// but this is not documented in the msdn entry for RtlAlloateHeap
	return allocateProcessHeap(size, *Ntdll.pNtdllBaseTag | 0xC0000);
}
