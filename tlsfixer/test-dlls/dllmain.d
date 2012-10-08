module dllmain;

import std.c.windows.windows;
import core.sys.windows.dll;

enum int tlsVarDesiredValue = mixin(import("tlsVarDesiredValue"));
static assert(tlsVarDesiredValue / 100 == 10);

extern(C) __gshared extern int _tls_index;
int tlsVar = tlsVarDesiredValue;

export extern(C) nothrow
{
	int getTLSIndex() { return _tls_index; }

	int getTLSVarValue() { return tlsVar; }

	void incrementTLSVar() { ++tlsVar; }

	int getTLSVarDesiredValue() { return tlsVarDesiredValue; }
}

extern (Windows)
BOOL DllMain(HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved) nothrow
{
	return true;
}
