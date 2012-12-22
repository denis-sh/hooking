/** TLS fixer DllMain

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.dllmain;

import core.sys.windows.windows;
import core.sys.windows.dll;

import tlsfixer.tlsfixes;


extern(Windows) BOOL DllMain(HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved)
{
	final switch (ulReason)
	{
	case DLL_PROCESS_ATTACH:
		dll_process_attach(hInstance, true);
		fixLibraryLoading();
		break;

	case DLL_PROCESS_DETACH:
		// TODO unfix library loading
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return true;
}
