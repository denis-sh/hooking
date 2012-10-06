module tlsfixer.utils;

// From lge.utils.math:

import core.bitop: bsr;

/// Returnes $(D true) iff $(D n) is a power of 2
bool isPowerOf2(uint n) pure nothrow
in { assert(n > 0); }
body { return !((n - 1) & n); }

unittest
{
	assert(isPowerOf2(1));
	assert(isPowerOf2(2));
	assert(!isPowerOf2(3));
	assert(isPowerOf2(4));
	assert(!isPowerOf2(5));
}


/// Returnes smallest power of 2 which >= $(D n)
int toPowerOf2(uint n) pure nothrow
in { assert(n > 0); }
body { return 1 << (bsr(n) + !isPowerOf2(n)); }

unittest
{
	static assert(toPowerOf2(1) == 1);
	static assert(toPowerOf2(2) == 2);
	static assert(toPowerOf2(3) == 4);
	static assert(toPowerOf2(4) == 4);
	static assert(toPowerOf2(5) == 8);
}
