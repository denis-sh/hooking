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

debug enum tlsFixerHasTLS = true;
else enum tlsFixerHasTLS = false;

struct TLSDLL
{
	HMODULE h;
	int tlsIndex;

	void test(size_t testIndex = 0)
	{
		auto call(T = GetIntFunc)(string name)
		{
			return enforce(cast(T) GetProcAddress(h, toStringz(name)), "Can't find `" ~ name ~ "`")();
		}

		immutable int tlsIndex = call("getTLSIndex");

		assert(tlsLoaded == !!tlsIndex);
		enforce(tlsIndex == this.tlsIndex + tlsFixerHasTLS * tlsLoaded, "Incorrect TLS index");


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


	@disable this();

	this(int tlsIndex, in char[] name)
	{
		this.tlsIndex = tlsIndex;
		const pathW = toUTF16z(dllRoot ~ name ~ ".dll");
		enforce(!GetModuleHandleW(pathW), format("'%s' is already loaded", name));
		h = enforce(LoadLibraryW(pathW), format("Failed to load '%s'", name));
		test(0);
	}

	void unload(size_t testIndex = 1)
	{
		test(testIndex);
		char ch;
		enforce(GetModuleFileNameA(h, &ch, 1) == 1, "DLL is not loaded");
		enforce(FreeLibrary(h), "Failed to unload DLL");
		enforce(!GetModuleFileNameA(h, &ch, 1), "DLL is still loaded");
		h = null;
	}
}


void main()
{
	enforce(cast(ubyte) GetVersion() < 6, "TLS problem is fixed in Windwos Vista and later, this test has no sense");

	// Unfixed: tlsLoaded = false, currTLSIndex = 0
	auto testC = TLSDLL(0, "test-C-1");
	auto testD1 = TLSDLL(0, "test-D-1");
	testC.unload();
	testD1.unload();


	// Fixed
	enforce(LoadLibraryA("TLSFixerDLL"));
	tlsLoaded = true;

	testC = TLSDLL(1, "test-C-1");
	testD1 = TLSDLL(2, "test-D-1");
	testC.unload();
	testD1.unload();

	testD1 = TLSDLL(1, "test-D-1");
	testC = TLSDLL(2, "test-C-1");
	auto testD2 = TLSDLL(3, "test-D-2");
	auto testD3 = TLSDLL(4, "test-D-3");

	__gshared TLSDLL testC3 = void;

	auto t = new Thread(
	{
		testC.test();
		testD1.test();
		testD1.test(1);
		testC.test(1);
		testD2.test();
		testD3.test();

		auto testC2 = TLSDLL(5, "test-C-2");
		testC3 = TLSDLL(6, "test-C-3");
		testC2.unload();
		testC3.test(1);
	});
	t.start();
	t.join();

	testC3.unload(0);

	testD1.unload();
	testC.unload();
	testD2.unload();
	testD3.unload();
}
