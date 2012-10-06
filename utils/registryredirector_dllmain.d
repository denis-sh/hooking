/** Windows Registry redirector DllMain

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module utils.registryredirector_dllmain;

import core.stdc.stdio;
import std.c.windows.windows;
import core.sys.windows.dll;

import utils.registryredirector;


__gshared HINSTANCE g_hInst;

extern (Windows)
BOOL DllMain(HINSTANCE hInstance, ULONG ulReason, LPVOID pvReserved)
{
	final switch (ulReason)
	{
	case DLL_PROCESS_ATTACH:
		//MessageBoxA(null, "RegistryRedirectorDLL.DllMain", "DllMain", MB_OK | MB_ICONINFORMATION);
		//AllocConsole();
		//SetConsoleTitleA("RegistryRedirectorDLL.DllMain XXXD");
		puts("RegistryRedirectorDLL.DllMain");
		g_hInst = hInstance;
		dll_process_attach(hInstance, true);
		try injectRedirection();
		catch(Throwable e)
			MessageBoxA(null, ("injectRedirection failed:\n" ~ e.toString()).ptr,
				"RegistryRedirectorDLL.DllMain", MB_OK | MB_ICONERROR);
		break;

	case DLL_PROCESS_DETACH:
		dll_process_detach(hInstance, true);
		break;

	case DLL_THREAD_ATTACH:
		dll_thread_attach(true, true);
		break;

	case DLL_THREAD_DETACH:
		dll_thread_detach(true, true);
		break;
	}
	return true;
}

