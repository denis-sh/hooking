/** Functions for function interception

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.x86.interceptor;

import core.sys.windows.windows;
import std.exception;
import std.string;

import hooking.windows.processmemory;


static assert(size_t.sizeof == 4);

enum pushedBytes = 36;

void nakedHelper(alias callTarget, size_t jmpTarget, string originCode)()
{
	mixin(format(`
	asm
	{
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
		format("Unexpected bytes at 0x%X: %(%X %) instead of %(%X %)", ptr, ptr[0 .. n], cast(ubyte[]) originCode));

	insertJump(ptr, n, cast(const(void*)) &helper);


	ptr = cast(ubyte*) &helper + 10 + n;
	enforce(*(ptr - 1) == 0xE9); // JMP rel32
	enforce(*cast(size_t*) ptr == address + n);
	
	auto memory = ProcessMemory.current;
	DWORD oldProtect = memory.changeProtection(cast(size_t) ptr, 4, PAGE_EXECUTE_READWRITE);
	*cast(size_t*) ptr -= cast(size_t) ptr + 4;
	memory.changeProtection(cast(size_t) ptr, 4, oldProtect);
	enforce(FlushInstructionCache(memory.processHandle, ptr, 4));
}

import std.traits;

// FIXME: hijacked function can jump to its start so we need to unhijack it first.
void hijackFunction(T: F*, F)(void* originAddress, string originCode, T func) if(is(F == function))
/*if(is(F == function) && is(ParameterTypeTuple!F Args) &&
is(ReturnType!(Args[0]) == ReturnType!F) && is(ParameterTypeTuple!(Args[0]) == Args[1 .. $]))*/
in { assert(originCode.length >= 5); }
body
{
	alias ParameterTypeTuple!F HijackedArgs;
	alias HijackedArgs[1 .. $] Args;
	static assert(HijackedArgs.length >= 1);
	static assert(is(ReturnType!(HijackedArgs[0]) == ReturnType!F));
	static assert(is(ParameterTypeTuple!(HijackedArgs[0]) == Args));

	ubyte* optr = cast(ubyte*) originAddress;
	immutable n = originCode.length;
	enforce(optr[0 .. n] == originCode,
		format("%(%X %) instead of %(%X %)", optr[0 .. n], cast(ubyte[]) originCode));

	ubyte* mptr = cast(ubyte*) enforce
		(VirtualAllocEx(GetCurrentProcess(), null, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	// Original code prefix
	const moptr = mptr;
	writeAsm(mptr, originCode);
	writeRel32(mptr, 0xE9, originAddress + n);

	// Our code
	insertJump(optr, n, mptr);

	writeAsm(mptr, x"55 89E5"); // push ebp; mov ebp, esp;
	foreach_reverse(i; 0 .. Args.length)
		writeAsms(mptr, x"FF 75", cast(ubyte) (8 + i * 4)); // push dword ptr [ebp+0x##] 
	writeAsms(mptr, x"68", moptr); // push imm32
	writeRel32(mptr, 0xE8, cast(void*) func); // call imm32
	writeAsms(mptr, x"5D C2", cast(ushort) (4 * Args.length)); // pop ebp; ret imm16;
}

unittest
{
	static int originalTestCalled = 0;

	static int originalTestImpl(int a, int b)
	{
		assert(a == 0x11);
		assert(b == 0x22);
		++originalTestCalled;
		return 0x33;
	}

	extern(Windows) static int originalTest(int a, int b)
	{
		asm
		{
			naked;
			push EBP;
			// Use "mov r32,r/m32", not "mov r/m32,r32"
			db 0x8B, 0xEC; // mov EBP, ESP; 
			nop; nop;
			push dword ptr [EBP+8];
			mov EAX, [EBP+0xc];
			call originalTestImpl;
			pop EBP;
			ret 8;
		}
	}

	extern(Windows) static int myTest(typeof(&originalTest) origin, int a, int b)
	{
		assert(a == 0x44);
		assert(b == 0x55);
		return origin(b / 5, a / 2) * 2;
	}


	assert(originalTest(0x11, 0x22) == 0x33 && originalTestCalled == 1);
	hijackFunction(cast(void*) &originalTest,
		x"55 8BEC 90 90" /*push ebp; mov ebp, esp; nop; nop;*/,
		&myTest);
	assert(originalTest(0x44, 0x55) == 0x66 && originalTestCalled == 2);
}

private:

void insertJump(ubyte* ptr, size_t n, const(void)* target)
in { assert(n >= 5); }
body
{
	auto memory = ProcessMemory.current;
	DWORD oldProtect = memory.changeProtection(cast(size_t) ptr, n, PAGE_EXECUTE_READWRITE);
	*ptr = 0xE9; // JMP rel32
	*cast(const(void)**) (ptr+1) = target - (cast(size_t) ptr + 5);
	foreach(i; 5 .. n)
		*(ptr + i) = 0xCC; // INT3
	memory.changeProtection(cast(size_t) ptr, n, oldProtect);
	enforce(FlushInstructionCache(memory.processHandle, ptr, n));
}

void writeAsm(T)(ref ubyte* ptr, in T[] tarr...) nothrow
{
	auto barr = cast(const(ubyte)[]) tarr;
	ptr[0 .. barr.length] = barr[];
	ptr += barr.length;
}

void writeAsms(A...)(ref ubyte* ptr, A args) nothrow
{
	foreach(arg; args)
		writeAsm(ptr, arg);
}

void writeRel32(ref ubyte* ptr, ubyte op, void* target) nothrow
{
	*ptr = op;
	*cast(const(void)**) (ptr+1) = target - (cast(size_t) ptr + 5);
	ptr += 5;
}