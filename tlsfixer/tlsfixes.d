/** Functions for fixing Windows Server 2003 and Windows XP problems
with thread-local variables in dynamically loaded DLLs

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.tlsfixes;

import std.c.windows.windows;
import tlsfixer.dlltls;
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
	if(cast(ubyte) GetVersion() >= 6) // Windwos Vista or later
		return;
	if(libraryLoadingFixed)
		return;

	alias LONG NTSTATUS;
	alias extern(Windows) NTSTATUS function(ULONG Flags, ULONG *State, ULONG *Cookie) LdrLockLoaderLockType;
	alias extern(Windows) NTSTATUS function(ULONG Flags, ULONG Cookie) LdrUnlockLoaderLockType;

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

	// push ESI; push EDI; push EBX; mov ESI, ESP;
	insertCall!(nakedTlsFixer!beforeDllMainCalled, 0x7C901179, x"56  57  53  8BF4")();

	// pop EBP; retn 10; nop;
	insertCall!(nakedTlsFixer!afterDllMainCalled, 0x7C90118F, x"5D C2 10 00 90")();

	// push 0xA0; RtlFreeHeap function
	insertCall!(nakedOnRtlFreeHeapCalled, 0x7C90FF2D, x"68 A0 00 00 00")();
	//insertCall!(nakedOnRtlFreeHeapCalled, 0x7C90FF3C, x"8B 7D 08 89 7D C8")();

	// Insert our hook in the memory freeing function (something like LdrpFreeTls in ReactOS)
	// called by LdrShutdownThread just before function that calls RtlLeaveCriticalSection
	// mov ESI, dword ptr DS:[EAX + 0x2C]; test ESI, ESI;
	insertCall!(nakedOnLdrShutdownThread, 0x7C9139A8, x"8B 70 2C 85 F6")();


	libraryLoadingFixed = true;
}

void validateLoadedModules() {
	//auto modules = getCurruptedModules();
}

private:

shared bool libraryLoadingFixed = false;

void nakedTlsFixer(alias f)() nothrow {
	asm {
		naked;
		// beforeDllMainCalled(hinstDLL, reason);
		push dword ptr [EBP+0xC];
		push dword ptr [EBP+0x10];
		mov EAX, [EBP+0x14];
		call f;
		ret;
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