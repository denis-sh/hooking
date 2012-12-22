module dlloader;

import core.sys.windows.windows;
import core.thread;
import std.utf: toUTF16z;
import std.exception: enforce;
import std.string: toStringz;


alias extern(C) void function() nothrow VoidFunc;
alias extern(C) int  function() nothrow GetIntFunc;
enum dllRoot = `tlsfixer\test-dlls\`;


shared bool tlsLoaded = false;
shared int currTLSIndex = 0;

void testLibrary(HANDLE h, size_t testIndex = 0)
{
	auto call(T = GetIntFunc)(string name)
	{
		return enforce(cast(T) GetProcAddress(h, toStringz(name)), "Can't find `" ~ name ~ "`")();
	}

	immutable int tlsIndex = call("getTLSIndex");

	assert(tlsLoaded == !!tlsIndex);
	enforce(tlsIndex == currTLSIndex + tlsLoaded);


	immutable int tlsVarDesiredValue = call("getTLSVarDesiredValue");
	enforce(tlsVarDesiredValue / 100 == 10);

	if(tlsLoaded)
	{
		immutable int tlsVarValue = call("getTLSVarValue");
		enforce(tlsVarValue == tlsVarDesiredValue + testIndex);
		call!VoidFunc("incrementTLSVar");
		enforce(tlsVarDesiredValue == call("getTLSVarDesiredValue"));
		enforce(tlsVarValue + 1 == call("getTLSVarValue"));
	}
}


HANDLE loadAndTest(in string name)
{
	HANDLE h = enforce(LoadLibraryW(toUTF16z(dllRoot ~ name ~ ".dll")));
	testLibrary(h);
	return h;
}


void main()
{
	enforce(cast(ubyte) GetVersion() < 6, "TLS problem is fixed in Windwos Vista and later, this test has no sense");

	// Unfixed: tlsLoaded = false, currTLSIndex = 0
	HANDLE testC = loadAndTest("test-C");
	HANDLE testD1 = loadAndTest("test-D-1");
	FreeLibrary(testC);
	testLibrary(testD1);
	FreeLibrary(testD1);


	// Fixed
	enforce(LoadLibraryA("TLSFixerDLL"));
	tlsLoaded = true;
	
	currTLSIndex = 1;
	testC = loadAndTest("test-C");
	currTLSIndex = 2;
	testD1 = loadAndTest("test-D-1");
	FreeLibrary(testC);
	testLibrary(testD1, 1);
	FreeLibrary(testD1);

	currTLSIndex = 1;
	testD1 = loadAndTest("test-D-1");
	currTLSIndex = 2;
	testC = loadAndTest("test-C");
	currTLSIndex = 3;
	HANDLE testD2 = loadAndTest("test-D-2");
	currTLSIndex = 4;
	HANDLE testD3 = loadAndTest("test-D-3");


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
	});
	t.start();
	t.join();

	currTLSIndex = 1;
	testLibrary(testD1, 1);
	FreeLibrary(testD1);
	currTLSIndex = 2;
	testLibrary(testC, 1);
	FreeLibrary(testC);
	currTLSIndex = 3;
	testLibrary(testD2, 1);
	FreeLibrary(testD2);
	currTLSIndex = 4;
	testLibrary(testD3, 1);
	FreeLibrary(testD3);
}