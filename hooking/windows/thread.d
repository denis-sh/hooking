/** Functions for thread manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.thread;

import core.sys.windows.windows;
import std.exception;


struct Thread
{
	private HANDLE handle;

	void executeUntil(size_t address)
	{
		enforce(ResumeThread(handle) != -1);
		for(size_t i = 0; ;++i)
		{
			Sleep(20);
			CONTEXT context;
			context.ContextFlags = CONTEXT_CONTROL;
			enforce(GetThreadContext(handle, &context));
			if(context.Eip == address)
				break;
			enforce(i < 50);
		}
		enforce(SuspendThread(handle) != -1);
	}
}
