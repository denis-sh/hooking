module tlsfixer.unittest_;

import core.sys.windows.windows;
import core.thread;
import std.utf: toUTF16z;
import std.exception: enforce;
import std.string: format, toStringz;


alias extern(C) void function() nothrow VoidFunc;
alias extern(C) int  function() nothrow GetIntFunc;
enum dllRoot = `tlsfixer\test-dlls\`;


shared bool tlsLoaded = false;
shared int currTLSIndex = 0;

debug enum tlsFixerHasTLS = true;
else enum tlsFixerHasTLS = false;

void testLibrary(HMODULE h, size_t testIndex = 0)
{
	auto call(T = GetIntFunc)(string name)
	{
		return enforce(cast(T) GetProcAddress(h, toStringz(name)), "Can't find `" ~ name ~ "`")();
	}

	immutable int tlsIndex = call("getTLSIndex");

	assert(tlsLoaded == !!tlsIndex);
	enforce(tlsIndex == currTLSIndex + tlsFixerHasTLS * tlsLoaded, "Incorrect TLS index");


	immutable int tlsVarDesiredValue = call("getTLSVarDesiredValue");
	enforce(tlsVarDesiredValue / 100 == 10, "Unexpected TLS variable desired value");

	if(tlsLoaded)
	{
		immutable int tlsVarValue = call("getTLSVarValue");
		enforce(tlsVarValue == tlsVarDesiredValue + testIndex, "Incorrect TLS variable value");
		call!VoidFunc("incrementTLSVar");
		enforce(tlsVarDesiredValue == call("getTLSVarDesiredValue"), "TLS variable desired value changed after increment");
		enforce(tlsVarValue + 1 == call("getTLSVarValue"), "Incorrect TLS variable value after increment");
	}
}


HMODULE loadAndTest(in char[] name)
{
	const pathW = toUTF16z(dllRoot ~ name ~ ".dll");
	enforce(!GetModuleHandleW(pathW), format("'%s' is already loaded", name));
	HMODULE h = enforce(LoadLibraryW(pathW), format("Failed to load '%s'", name));
	testLibrary(h, 0);
	return h;
}

void unload(HMODULE h)
{
	char ch;
	enforce(GetModuleFileNameA(h, &ch, 1) == 1, "DLL is not loaded");
	enforce(FreeLibrary(h), "Failed to unload DLL");
	enforce(!GetModuleFileNameA(h, &ch, 1), "DLL is still loaded");
}


void main()
{
	enforce(cast(ubyte) GetVersion() < 6, "TLS problem is fixed in Windwos Vista and later, this test has no sense");

	// Unfixed: tlsLoaded = false, currTLSIndex = 0
	HMODULE testC = loadAndTest("test-C-1");
	HMODULE testD1 = loadAndTest("test-D-1");
	unload(testC);
	testLibrary(testD1);
	unload(testD1);


	// Fixed
	enforce(LoadLibraryA("TLSFixerDLL"));
	tlsLoaded = true;

	currTLSIndex = 1;
	testC = loadAndTest("test-C-1");
	currTLSIndex = 2;
	testD1 = loadAndTest("test-D-1");
	unload(testC);
	testLibrary(testD1, 1);
	unload(testD1);

	currTLSIndex = 1;
	testD1 = loadAndTest("test-D-1");
	currTLSIndex = 2;
	testC = loadAndTest("test-C-1");
	currTLSIndex = 3;
	HMODULE testD2 = loadAndTest("test-D-2");
	currTLSIndex = 4;
	HMODULE testD3 = loadAndTest("test-D-3");
	__gshared HMODULE testC3;


	auto t = new Thread(
	{
		currTLSIndex = 2;
		testLibrary(testC);
		currTLSIndex = 1;
		testLibrary(testD1);
		testLibrary(testD1, 1);
		currTLSIndex = 2;
		testLibrary(testC, 1);
		currTLSIndex = 3;
		testLibrary(testD2);
		currTLSIndex = 4;
		testLibrary(testD3);

		currTLSIndex = 5;
		HMODULE testC2 = loadAndTest("test-C-2");
		currTLSIndex = 6;
		testC3 = loadAndTest("test-C-3");
		currTLSIndex = 5;
		testLibrary(testC2, 1);
		unload(testC2);
		currTLSIndex = 6;
		testLibrary(testC3, 1);
	});
	t.start();
	t.join();

	currTLSIndex = 6;
	testLibrary(testC3);
	unload(testC3);

	currTLSIndex = 1;
	testLibrary(testD1, 1);
	unload(testD1);
	currTLSIndex = 2;
	testLibrary(testC, 1);
	unload(testC);
	currTLSIndex = 3;
	testLibrary(testD2, 1);
	unload(testD2);
	currTLSIndex = 4;
	testLibrary(testD3, 1);
	unload(testD3);
}
