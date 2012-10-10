/** Kernel32.dll private API

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.kernel32;

import core.sys.windows.windows;
import std.exception;

import hooking.x86.utils;

struct Kernel32
{
static:

	void load()
	{
		__gshared bool loaded = false;
		if(loaded)
			return;

		hmodule = enforce(GetModuleHandleA("Kernel32"));
		findBaseThunks();

		loaded = true;
	}

	@property extern(Windows) void function() nothrow BaseProcessStartThunk() nothrow
	{ return cast(typeof(return)) pBaseProcessStartThunk; }

	@property extern(Windows) void function() nothrow BaseThreadStartupThunk() nothrow
	{ return cast(typeof(return)) pBaseThreadStartupThunk; }

private:
	__gshared
	{
		HMODULE hmodule;
		void* pBaseProcessStartThunk, pBaseThreadStartupThunk;
	}

	// Searches for kernel32.Base{ProcessStart|ThreadStartup}Thunk addresses
	void findBaseThunks()
	{
		void* pCreateRemoteThread = enforce(GetProcAddress(hmodule, "CreateRemoteThread"));

		void* pLabel1 = enforce(findCodeReference(pCreateRemoteThread,
			0xA0, x"8D85 58FCFFFF  50  E8 ",  // lea EAX, dword ptr [EBP-0x3A8];  push EAX;  call __Label1;
			true));

		void* pLabel1_2 = enforce(findCodeSequence(pLabel1,
			0x80, x"8988 C4000000  0F85 "    // mov dword ptr [EAX+0xC4], ECX;  jnz __Label2;
			));

		void* pBaseThreadStartupThunk = getAbsoluteTarget(pLabel1_2
			+ 4 /* __Label2 */ + 6 // C780 B8000000 <BaseThreadStartupThunk>; // mov dword ptr [EAX+0xB8], BaseThreadStartupThunk;
		);

		enforce(pBaseThreadStartupThunk[0 .. 6] ==
			x"33ED  53  50  6A 00" // xor EBP, EBP;  push EBX;  push EAX;  push 0; // BaseThreadStartupThunk
		);

		void* pLabel2 = getRelativeTarget(pLabel1_2);

		pBaseProcessStartThunk = enforce(findCodeReference(pLabel2,
			0xF, x"C780 B8000000 ",  // mov dword ptr [EAX+0xB8], BaseProcessStartThunk;
			false));

		enforce(pBaseProcessStartThunk[0 .. 5] ==
			x"33ED  50  6A 00" // xor EBP, EBP;  push EAX;  push 0; // BaseProcessStartThunk
		);
	}
}
