/** Functions for simple Windows Registry redirection

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module utils.registryredirector;

import std.regex;
import std.array;
import std.stdio;
import std.getopt;
import std.algorithm;
import std.exception;
import std.traits;
import std.typetuple;
import std.process;
import std.string;
import std.conv;
import std.utf;
import core.stdc.string;
import core.sys.windows.windows;

import hooking.x86.interceptor;


// A copy of private std.regex.BasicElementOf
template BasicElementOf(Range)
{
	import std.range;
	alias Unqual!(ElementEncodingType!Range) BasicElementOf;
}

// A copy of private std.regex.isRegexFor
template isRegexFor(RegEx, R)
{
	enum isRegexFor = is(RegEx == Regex!(BasicElementOf!R))
                 || is(RegEx == StaticRegex!(BasicElementOf!R));
}

public @trusted R myReplace(R, RegEx)(R input, RegEx re, R format)
if(isSomeString!R && isRegexFor!(RegEx, R))
{
    auto matches = match(input, re);
	if(matches.empty)
		return null;
	auto m = matches.front;
	if(!m.pre.empty || !m.post.empty)
		return null;

	auto app = appender!(R)();
	replaceFmt(format, m.captures, app);
    return app.data;
}

const(HKEY) redirect(T)(in HKEY hKey, ref const(T)* lpSubKey) if(is(T == char) || is(T == wchar)) {
	string originKey;
	if(hKey == HKEY_CLASSES_ROOT  ) originKey = "HKCR"; else
	if(hKey == HKEY_CURRENT_USER  ) originKey = "HKCU"; else
	if(hKey == HKEY_LOCAL_MACHINE ) originKey = "HKLM"; else
	if(hKey == HKEY_USERS         ) originKey = "HKU" ; else
	if(hKey == HKEY_CURRENT_CONFIG) originKey = "HKCC"; else
	return hKey;

	if(lpSubKey) {
		originKey ~= `\`;
		static if(is(T == char))
			originKey ~= lpSubKey[0 .. strlen(lpSubKey)];
		else
			originKey ~= to!string(lpSubKey[0 .. std.string.wcslen(lpSubKey)]);
	}
	foreach(r; redirections) if(string newKey = myReplace(originKey, r.from, r.to)) {
		//MessageBoxA(null, toStringz(originKey~'\n'~newKey), "RegistryRedirectorDLL", MB_OK | MB_ICONINFORMATION);
		HKEY newHKey;
		if(newKey.skipOver("HKCR")) newHKey = HKEY_CLASSES_ROOT; else
		if(newKey.skipOver("HKCU")) newHKey = HKEY_CURRENT_USER; else
		if(newKey.skipOver("HKLM")) newHKey = HKEY_LOCAL_MACHINE; else
		if(newKey.skipOver("HKU" )) newHKey = HKEY_USERS; else
		if(newKey.skipOver("HKCC")) newHKey = HKEY_CURRENT_CONFIG; else
		assert(0);
		if(newKey.empty)
			lpSubKey = null;
		else {
			enforce(newKey.skipOver(`\`));
			static if(is(T == char))
				lpSubKey = toStringz(newKey);
			else
				lpSubKey = toUTF16z(newKey);
		}
		return newHKey;
	}
	if(originKey.startsWith(`HKLM\SOFTWARE\Gromada`))
		MessageBoxA(null, toStringz(originKey~'\n'~"no match"), "RegistryRedirectorDLL", MB_OK | MB_ICONINFORMATION);
	return hKey;
}

extern(Windows) {
	export LONG RegCreateKeyA(in HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
    export LONG RegCreateKeyW(in HKEY hKey, LPCWSTR lpSubKey, PHKEY phkResult);

	LONG myReg(alias func)(typeof(&func) origin, ParameterTypeTuple!func Args) {
		try {
			auto lpSubKey = Args[1];
			return origin(redirect(Args[0], lpSubKey), lpSubKey, Args[2 .. $]);
		} catch(Throwable e)
			MessageBoxA(null, (myReg.stringof~" failed:\n" ~ e.toString()).ptr,
						"RegistryRedirectorDLL.myReg", MB_OK | MB_ICONERROR);
		return 1;
	}
}

struct Redir {
	Regex!char from;
	string to;
}

Redir[] redirections;

void injectRedirection() {
	// HKLM(\\SOFTWARE\\App.*)->HKCU$1
	redirections = environment["REG_REDIRECTIONS"].splitter(';').map!((a) {
		//MessageBoxA(null, toStringz(a), "", MB_OK | MB_ICONINFORMATION);
		size_t i = std.string.indexOf(a, "->");
		//MessageBoxA(null, toStringz(a[i + 2 .. $]), toStringz(a[0 .. i]), MB_OK | MB_ICONINFORMATION);
		return Redir(regex(a[0 .. i], "g"), a[i + 2 .. $]);
	})().array();
	HMODULE Advapi32 = enforce(GetModuleHandleA("Advapi32"));
	auto prefix = 
		x"8BFF"  // MOV EDI,EDI
		x"55"    // PUSH EBP
		x"8BEC"  // MOV EBP,ESP
		;
	foreach(func0; TypeTuple!("RegOpenKey", "RegCreateKey"))
	foreach(func1; TypeTuple!(func0, func0 ~ "Ex"))
	foreach(func; TypeTuple!(func1 ~ 'A', func1 ~ 'W'))
		mixin(`hijackFunction(cast(void*) enforce(GetProcAddress(Advapi32, "`~func~`")), prefix, &myReg!`~func~`);`);
	puts("Registry redirection injected.");
}
