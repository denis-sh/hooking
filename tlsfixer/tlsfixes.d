/** Functions for fixing Windows Server 2003 and Windows XP problems
with thread-local variables in dynamically loaded DLLs

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.tlsfixes;

import std.c.windows.windows;
import tlsfixer.ntdll;
import tlsfixer.dlltls;
import hooking.x86.utils;

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

	enforceErr(Ntdll.load());

	auto ntdll = GetModuleHandleA("ntdll");

	ULONG cookie;
	Ntdll.LdrLockLoaderLock(1, null, &cookie);
	scope(exit) Ntdll.LdrUnlockLoaderLock(1, cookie);
	if(libraryLoadingFixed) return;

	initializeDllTlsModule();

	void* dllMainCallAddress;
	{
		void* pLdrLoadDll = enforceErr(GetProcAddress(ntdll, "LdrLoadDll"));

		void* pFunc1 = enforceErr(findCodeReference(pLdrLoadDll,
			0x120, x"FFB5 C0FDFFFF  E8 ",  // ... call __Func1;
			true));

		void* pLabel2 = enforceErr(findCodeReference(pFunc1,
			0x90, x"66 8B08  66 3BCB  0F84 ",  // ... je __Label2;
			true));

		void* pFunc3 = enforceErr(findCodeReference(pLabel2,
			0x200, x"FFB5 C8FDFFFF  FFD0  C745 FC 02000000  53  E8 ",  // ... call __Func3;
			true));

		void* pLabel4 = enforceErr(findCodeReference(pFunc3,
			0x200, x"8B45 E0  8945 D8  EB ",  // ... jmp short __Label4;
			true, 1));

		void* pFunc5 = enforceErr(findCodeReference(pLabel4,
			0x130, x"47  57  FF76 18  53  E8 ",  // ... call __Func5;
			true));

		dllMainCallAddress = enforceErr(findCodeSequence(pFunc5,
			0x15, x"FF75 10  FF75 0C"));
	}

	insertJump(
		cast(void*) &nakedDllMainCaller + (/*push*/ 3 + /*call*/ 5 + /*mov*/ 2),
		x"CC CC CC CC CC",
		dllMainCallAddress + 5
	);

	insertJump(
		dllMainCallAddress,
		x"FF55 08  8BE6", // call [EBP+8]; mov ESP, ESI;
		&nakedDllMainCaller
	);


	// Insert our hook in the memory freeing function (something like LdrpFreeTls in ReactOS)
	// called by LdrShutdownThread just before function that calls RtlLeaveCriticalSection

	void* inLdrpFreeTls;
	{
		void* pLdrShutdownThread = enforceErr(GetProcAddress(ntdll, "LdrShutdownThread"));

		void* pLabel1 = enforceErr(findCodeReference(pLdrShutdownThread,
			0x40, x"8B58 20  895D E4  EB ",  // ... jmp short __Label1;
			true, 1));

		void* pLabel2 = enforceErr(findCodeReference(pLabel1,
			0x40, x"3BD8  0F84 ",  // ... je __Label2;
			true));

		void* pLabel3 = getRelativeTarget(pLabel2 + 0xE);

		inLdrpFreeTls = pLabel3 + 9;
	}

	insertJump(
		cast(void*) &nakedOnLdrShutdownThread + (/*push EAX*/ 1 + /*call*/ 5 + /*pop EAX*/ 1 + /*origin code*/ 5),
		x"CC CC CC CC CC",
		inLdrpFreeTls + 5
	);

	insertJump(
		inLdrpFreeTls,
		x"8B70 2C  85F6", // mov ESI, dword ptr DS:[EAX + 0x2C]; test ESI, ESI;
		&nakedOnLdrShutdownThread
	);


	libraryLoadingFixed = true;
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

void nakedOnLdrShutdownThread() nothrow
{
	asm {
		naked;
		push EAX;
		call windowsOnLdrShutdownThread;
		pop EAX;
		mov ESI, dword ptr DS:[EAX + 0x2C];
		test ESI, ESI;
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

	void windowsOnLdrShutdownThread() nothrow
	{
		onLdrShutdownThread();
	}
}

// (with DisableThreadLibraryCalls)
void beforeDllMainCalled(HINSTANCE hinstDLL, DWORD reason, LPVOID reserved) nothrow
in { assert(reason < 4, "Unexpected reason"); }
body {
	debug(tlsfixes) {
		char[MAX_PATH + 1] s;
		enforceErr(GetModuleFileNameA(hinstDLL, s.ptr, s.length));
		const debug_itd = getImageTlsDirectory(hinstDLL);
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
	
	const itd = getImageTlsDirectory(hinstDLL);
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

	const itd = getImageTlsDirectory(hinstDLL);
	if(!itd)
		return; // No implicit TLS
	debug(tlsfixes) puts("Freeing TLS...");

	bool done = freeDllTls(hinstDLL, cast(int*) itd.AddressOfIndex);
	assert(done);
}

void insertJump(void* originAddress, in char[] originCode, const(void)* target)
in { assert(originCode.length >= 5); }
body
{
	ubyte* ptr = cast(ubyte*) originAddress;
	immutable n = originCode.length;
	import core.stdc.string: memcmp;
	enforceErr(memcmp(ptr, originCode.ptr, n) == 0);

	auto processHandle = enforceErr(GetCurrentProcess());
	DWORD oldProtection;
	enforceErr(VirtualProtectEx(processHandle, ptr, n, PAGE_EXECUTE_READWRITE, &oldProtection));
	*ptr = 0xE9; // JMP rel32
	*cast(const(void)**) (ptr+1) = target - (cast(size_t) ptr + 5);
	foreach(i; 5 .. n)
		*(ptr + i) = 0xCC; // INT3
	enforceErr(VirtualProtectEx(processHandle, ptr, n, oldProtection, &oldProtection));
	enforceErr(FlushInstructionCache(processHandle, ptr, n));
}
