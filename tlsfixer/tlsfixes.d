/** Functions for fixing Windows Server 2003 and Windows XP problems
with thread-local variables in dynamically loaded DLLs

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.tlsfixes;

import core.sys.windows.windows;
import tlsfixer.ntdll;
import tlsfixer.winutils;
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
void fixLibraryLoading()
{
	if(cast(ubyte) GetVersion() >= 6) // Windows Vista or later
		return;
	if(libraryLoadingFixed)
		return;

	enforceErr(Ntdll.load());
	initWinUtils();

	initializeDllTlsModule();

	void* dllMainCallAddress;
	{
		void* pLdrLoadDll = enforceErr(GetProcAddress(Ntdll.hmodule, "LdrLoadDll"));

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
		void* pLdrShutdownThread = enforceErr(GetProcAddress(Ntdll.hmodule, "LdrShutdownThread"));

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

void nakedDllMainCaller() nothrow
{
	asm
	{
		naked;
		push dword ptr [EBP+8];
		call dllMainCaller;
		mov ESP, ESI;
		db 0xCC, 0xCC, 0xCC, 0xCC, 0xCC; // will be replced with JMP back
	}
}

void nakedOnLdrShutdownThread() nothrow
{
	asm
	{
		naked;
		push EAX;
		call windowsOnLdrShutdownThread;
		pop EAX;
		mov ESI, dword ptr DS:[EAX + 0x2C];
		test ESI, ESI;
		db 0xCC, 0xCC, 0xCC, 0xCC, 0xCC; // will be replced with JMP back
	}
}

extern (Windows)
{
	alias BOOL function(HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved) DllMainType;

	BOOL dllMainCaller(DllMainType dllMain, HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved)
	{
		debug(tlsfixes)
		{
			char[MAX_PATH + 1] buff;
			char[] moduleName = buff[0 .. GetModuleFileNameA(hInstance, buff.ptr, buff.length)];
			enforceErr(moduleName.length);
			foreach_reverse(i, ch; moduleName) if(ch == '\\')
			{ moduleName = moduleName[i + 1 .. $]; break; }
			if(moduleName.length > 3 && moduleName[$ - 4] == '.')
				moduleName[$ - 4] = '\0';
			const debug_itd = getImageTlsDirectory(hInstance);
			if(debug_itd)
			{
				final switch(ulReason)
				{
					case 1: printf("DLL_PROCESS_ATTACH (loaded %s)",
								pvReserved is null ? "dynamically".ptr : "statically".ptr);
						break;
					case 0: printf("DLL_PROCESS_DETACH (%s)",
								pvReserved is null ? "FreeLibrary or failed DLL load".ptr : "process is terminating".ptr);
						break;
					case 2: printf("DLL_THREAD_ATTACH"); break;
					case 3: printf("DLL_THREAD_DETACH"); break;
				}
				printf(": %X, %s\n", hInstance, moduleName.ptr);
			}
		}

		assert(ulReason < 4, "Unexpected reason");

		// Set TLS directory for DLL_PROCESS_ATTACH (1) and DLL_PROCESS_DETACH (0)
		const imageTlsDirectory = (ulReason & ~1) == 0 ? getImageTlsDirectory(hInstance) : null;

		if(ulReason == 1 && imageTlsDirectory) // DLL_PROCESS_ATTACH and there is implicit TLS
			enforceErr(setDllTls(hInstance,
					cast(void*) imageTlsDirectory.StartAddressOfRawData,
					cast(void*) imageTlsDirectory.EndAddressOfRawData,
					cast(void*) imageTlsDirectory.AddressOfCallBacks,
					cast( int*) imageTlsDirectory.AddressOfIndex),
				"Can't set DLL TLS");

		immutable BOOL res = dllMain(hInstance, ulReason, pvReserved);

		if(ulReason == 0 && imageTlsDirectory) // DLL_PROCESS_DETACH and there is implicit TLS
			enforceErr(freeDllTls(hInstance,
					cast(int*) imageTlsDirectory.AddressOfIndex),
				"Can't free DLL TLS");

		return res;
	}

	void windowsOnLdrShutdownThread() nothrow
	{
		onLdrShutdownThread();
	}
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
