/** Functions for fixing Windows Server 2003 and Windows XP problems
with thread-local variables in dynamically loaded DLLs

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.tlsfixes;

import std.c.windows.windows;
import tlsfixer.dlltls;
import hooking.windows.c.winternl: NTSTATUS;
import hooking.windows.pe;
import hooking.x86.interceptor;
import std.exception;

debug(tlsfixes) import std.stdio;

/*
http://msdn.microsoft.com/en-us/library/windows/desktop/ms684175(v=vs.85).aspx

Windows Server 2003 and Windows XP:  The Visual C++ compiler supports a syntax that
enables you to declare thread-local variables: _declspec(thread). If you use this
syntax in a DLL, you will not be able to load the DLL explicitly using LoadLibrary
on versions of Windows prior to Windows Vista.
*/
void fixLibraryLoading() {
	if(cast(ubyte) GetVersion() >= 6) // Windows Vista or later
		return;
	if(libraryLoadingFixed)
		return;

	alias extern(Windows) NTSTATUS function(ULONG Flags, ULONG *State, ULONG *Cookie) nothrow LdrLockLoaderLockType;
	alias extern(Windows) NTSTATUS function(ULONG Flags, ULONG Cookie) nothrow LdrUnlockLoaderLockType;

	auto ntdll = GetModuleHandleA("ntdll");
	auto LdrLockLoaderLock   = cast(LdrLockLoaderLockType  ) enforce(GetProcAddress(ntdll, "LdrLockLoaderLock"));
	auto LdrUnlockLoaderLock = cast(LdrUnlockLoaderLockType) enforce(GetProcAddress(ntdll, "LdrUnlockLoaderLock"));

	ULONG cookie;
	LdrLockLoaderLock(1, null, &cookie);
	scope(exit) LdrUnlockLoaderLock(1, cookie);
	if(libraryLoadingFixed) return;

	initializeDllTlsModule();

	// NOTE: validateLoadedModules can throw an error
	// so LdrUnlockLoaderLock may not be called.
	validateLoadedModules();

	// FIXME: get addresses dynamically for current ntdll.dll
	// using `RtlFreeHeap` and `LdrShutdownThread` exported functions

	void* dllMainCallAddress = cast(void*) 0x7C901187;

	insertJump(
		cast(void*) &nakedDllMainCaller + (/*push*/ 3 + /*call*/ 5 + /*mov*/ 2),
		x"CC CC CC CC CC",
		dllMainCallAddress + 5
	);

	insertJump(
		cast(void*) 0x7C901187,
		x"FF55 08  8BE6", // call [EBP+8]; mov ESP, ESI;
		cast(const void*) &nakedDllMainCaller
	);


	insertCall!(nakedOnRtlFreeHeapCalled,
		0x7C90FF2D,    // RtlFreeHeap function
		x"68 A0000000" // push 0xA0;
		/+ or:
		0x7C90FF3C,          // in RtlFreeHeap function
		x"8B7D 08   897D C8" // mov EDI, [EBP+0x8]; mov [EBP-0x38], EDI;
		+/
	)();

	// Insert our hook in the memory freeing function (something like LdrpFreeTls in ReactOS)
	// called by LdrShutdownThread just before function that calls RtlLeaveCriticalSection
	insertCall!(nakedOnLdrShutdownThread,
		0x7C91A7D8,      // The target of first from the last three calls in LdrShutdownThread before return
		// On older ntdll.dll: 0x7C9139A8
		x"8B70 2C  85F6" // mov ESI, dword ptr DS:[EAX + 0x2C]; test ESI, ESI;
	)();


	libraryLoadingFixed = true;
}

void validateLoadedModules() {
	//auto modules = getCurruptedModules();
}

private:

shared bool libraryLoadingFixed = false;

void nakedDllMainCaller() nothrow {
	asm {
		naked;
		push dword ptr [EBP+8];
		call dllMainCaller;
		mov ESP, ESI;
		db 0xCC, 0xCC, 0xCC, 0xCC, 0xCC; // will be replced with JMP back
	}
}

extern (Windows) {
	alias BOOL function(HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved) DllMainType;

	BOOL dllMainCaller(DllMainType dllMain, HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved)
	{
		beforeDllMainCalled(hInstance, ulReason, pvReserved);
		immutable BOOL res = dllMain(hInstance, ulReason, pvReserved);
		afterDllMainCalled(hInstance, ulReason, pvReserved);
		return res;
	}
}

void nakedOnRtlFreeHeapCalled() nothrow {
	asm {
		naked;
		push EBP;
		mov EBP, ESP;
		push dword ptr [EBP+pushedBytes+8+4];
		push dword ptr [EBP+pushedBytes+8+4+4];
		mov EAX, [EBP+pushedBytes+8+4+8];
		call onRtlFreeHeapCalled;
		pop EBP;
		ret;
	}
}

void nakedOnLdrShutdownThread() nothrow {
	asm {
		naked;
		call onLdrShutdownThread;
		ret;
	}
}

// (with DisableThreadLibraryCalls)
void beforeDllMainCalled(HINSTANCE hinstDLL, DWORD reason, LPVOID reserved) nothrow
in { assert(reason < 4, "Unexpected reason"); }
body {
	debug(tlsfixes) {
		char[MAX_PATH + 1] s;
		try enforce(GetModuleFileNameA(hinstDLL, s.ptr, s.length)); catch { }
		const debug_itd = PEFile(hinstDLL, true).imageTlsDirectory;
		if(debug_itd) {
			final switch(reason) {
				case 1: printf("DLL_PROCESS_ATTACH (loaded %s)",
							reserved is null ? "dynamically".ptr : "statically".ptr);
					break;
				case 0: printf("DLL_PROCESS_DETACH (%s)",
							reserved is null ? "FreeLibrary or failed DLL load".ptr : "process is terminating".ptr);
					break;
				case 2: printf("DLL_THREAD_ATTACH"); break;
				case 3: printf("DLL_THREAD_DETACH"); break;
			}
			printf(": %X, %s\n", hinstDLL, s.ptr);
		}
	}

	if(reason != 1)
		return; // Not DLL_PROCESS_ATTACH
	
	const itd = PEFile(hinstDLL, true).imageTlsDirectory;
	if(!itd)
		return; // No implicit TLS
	debug(tlsfixes) puts("Setting TLS...");

	/*enum n = 1024 * 1024 * 100;
	__gshared void* p;
	if(!p) {
		p = core.stdc.stdlib.malloc(n);
		(cast(uint[])p[0..n])[] = 7;
	}*/
	bool done = setDllTls(hinstDLL,
		//p,p+n,
		cast(void*) itd.StartAddressOfRawData,
		cast(void*) itd.EndAddressOfRawData,
		cast(void*) itd.AddressOfCallBacks,
		cast( int*) itd.AddressOfIndex);
	assert(done);
}

void afterDllMainCalled(HINSTANCE hinstDLL, DWORD reason, LPVOID reserved) nothrow  {
	if(reason != 0)
		return; // Not DLL_PROCESS_DETACH

	const itd = PEFile(hinstDLL, true).imageTlsDirectory;
	if(!itd)
		return; // No implicit TLS
	debug(tlsfixes) puts("Freeing TLS...");

	bool done = freeDllTls(hinstDLL, cast(int*) itd.AddressOfIndex);
	assert(done);
}

//void onProcessAttach(HINSTANCE dllModule,