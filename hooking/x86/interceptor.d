/** Functions for function interception

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.x86.interceptor;

import std.c.windows.windows;
import std.exception;
import std.string;


static assert(size_t.sizeof == 4);

enum pushedBytes = 36;

void nakedHelper(alias callTarget, size_t jmpTarget, string originCode)() {
	mixin(xformat(`
	asm {
		naked;
		pushad;
		pushfd;
		call callTarget;
		popfd;
		popad;
		db %(0x%X, %);
		db 0xE9; dq jmpTarget;
	}`, cast(immutable(ubyte)[]) originCode));
}

void insertCall(alias f, size_t address, string originCode)()
{
	enum n = originCode.length;
	static assert(n >= 5);
	alias nakedHelper!(f, address + n, originCode) helper;

	ubyte* ptr = cast(ubyte*) address;
	enforce(ptr[0 .. n] == originCode,
		xformat("%(%X %) instead of %(%X %)", ptr[0 .. n], cast(ubyte[]) originCode));

	DWORD oldProtect = makeWriteable(ptr, n);
	*ptr = 0xE9; // JMP rel32
	*cast(const(void)**) (ptr+1) = cast(const(void*)) &helper - (cast(size_t) ptr + 5);
	static if(n > 5) foreach(i; 5 .. n)
		*(ptr + i) = 0x90; // NOP
	enforce(VirtualProtect(ptr, n, oldProtect, &oldProtect));
	enforce(FlushInstructionCache(GetCurrentProcess(), ptr, n));


	ptr = cast(ubyte*) &helper + 10 + n;
	enforce(*(ptr - 1) == 0xE9); // JMP rel32
	enforce(*cast(size_t*) ptr == address + n);
	
	oldProtect = makeWriteable(ptr, 4);
	*cast(size_t*) ptr -= cast(size_t) ptr + 4;
	enforce(VirtualProtect(ptr, 4, oldProtect, &oldProtect));
	enforce(FlushInstructionCache(GetCurrentProcess(), ptr, 4));
}

private:

extern(Windows)
BOOL IsBadWritePtr(in LPVOID lp,in UINT_PTR ucb);

DWORD makeWriteable(void* ptr, size_t size) {
	//enforce(IsBadWritePtr(ptr, size), "Alreasy accessed changed by some program");

	MEMORY_BASIC_INFORMATION mbi;
	enforce(VirtualQuery(ptr, &mbi, mbi.sizeof));
	auto tt = mbi.Protect;
	mbi.Protect &= ~(PAGE_READONLY|PAGE_EXECUTE_READ);
	mbi.Protect |= PAGE_EXECUTE_READWRITE;
	DWORD dwOld;
	enforce(VirtualProtect(ptr, size, mbi.Protect, &dwOld));
	assert(!IsBadWritePtr(ptr, size));
	return dwOld;
}
