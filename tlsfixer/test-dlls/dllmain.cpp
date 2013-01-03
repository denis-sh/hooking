#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <windows.h>


const int tlsVarDesiredValue = 
#include "tlsVarDesiredValue"
;

extern "C" extern int _tls_index;
__declspec(thread) int tlsVar = tlsVarDesiredValue;


#define EXPORTED_API extern "C" __declspec(dllexport)

EXPORTED_API int getTLSIndex() { return _tls_index; }

EXPORTED_API int getTLSVarValue() { return tlsVar; }

EXPORTED_API void incrementTLSVar() { ++tlsVar; }

EXPORTED_API int getTLSVarDesiredValue() { return tlsVarDesiredValue; }


BOOL APIENTRY DllMain(HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved)
{
	return true;
}
