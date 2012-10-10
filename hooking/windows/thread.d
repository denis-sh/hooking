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

	void suspend() { enforce(SuspendThread(handle) != -1); }

	void resume() { enforce(ResumeThread(handle) != -1); }


	/** Waits for thread's EIP to be fixed on $(D address) (e.g. because of a `JMP $-2;` loop).
	It will resume the thread if it is suspended and then increase suspended count with the same value.
	*/
	void executeUntil(size_t address)
	{
		DWORD suspendCount = ResumeThread(handle);
		enforce(suspendCount != -1);
		foreach(i; 1 .. suspendCount)
			resume();

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
		foreach(i; 0 .. suspendCount)
			suspend();
	}

	CONTEXT getContext(DWORD flags)
	{
		CONTEXT context;
		context.ContextFlags = flags;
		enforce(GetThreadContext(handle, &context));
		return context;
	}

	void setContext(CONTEXT context)
	{
		enforce(SetThreadContext(handle, &context));
	}

	void changeContext(DWORD getFlags, scope void delegate(ref CONTEXT) del)
	{
		CONTEXT context = getContext(getFlags);
		del(context);
		setContext(context);
	}
}
