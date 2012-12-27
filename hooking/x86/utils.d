/** Helper functions x86 instructions manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.x86.utils;

inout(void)* getAbsoluteTarget(inout(void)* address) nothrow
{
	return *cast(inout(void)**) address;
}

inout(void)* getRelativeTarget(inout(void)* address, ubyte addressSize = 4) nothrow
in { assert(addressSize == 1 || addressSize == 4); }
body
{
	return address + addressSize + 
		(addressSize == 1 ? *cast(byte*) address :
		*cast(int*) address);
}

/// Find a code sequence and return the address after the sequence
inout(void)* findCodeSequence(inout(void)* startAddress, size_t len, string pattern) nothrow
{
	if(startAddress)
		foreach(p; 0 .. len)
			if(startAddress[p .. p + pattern.length] == pattern)
				return startAddress + p + pattern.length;
	return null;
}

/// Find a code sequence and return the (relative) address that follows
inout(void)* findCodeReference(inout(void)* startAddress, size_t len, string pattern, bool relative, ubyte addressSize = 4) nothrow
in { assert(relative || addressSize == 4); }
body
{
	if(auto p = findCodeSequence(startAddress, len, pattern))
		return relative ? getRelativeTarget(p, addressSize) : getAbsoluteTarget(p);
	return null;
}
