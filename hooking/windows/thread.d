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
	package HANDLE _handle;
	package DWORD _threadId;

	invariant()
	{ assert(_handle || _threadId, "Attempting to use unassociated Thread struct"); }

	@property HANDLE handle()
	{ return _handle; }

	@property DWORD threadId() const
	{ return _threadId; }

	void suspend() { enforce(SuspendThread(_handle) != -1); }

	void resume() { enforce(ResumeThread(_handle) != -1); }


	/** Waits for thread's EIP to be fixed on $(D address) (e.g. because of a `JMP $-2;` loop).
	It will resume the thread if it is suspended and then increase suspended count with the same value.
	*/
	void executeUntil(size_t address)
	{
		DWORD suspendCount = ResumeThread(_handle);
		enforce(suspendCount != -1);
		foreach(i; 1 .. suspendCount)
			resume();

		for(size_t i = 0; ;++i)
		{
			Sleep(20);
			CONTEXT context;
			context.ContextFlags = CONTEXT_CONTROL;
			enforce(GetThreadContext(_handle, &context));
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
		enforce(GetThreadContext(_handle, &context));
		return context;
	}

	void setContext(CONTEXT context)
	{
		enforce(SetThreadContext(_handle, &context));
	}

	void changeContext(DWORD getFlags, scope void delegate(ref CONTEXT) del)
	{
		CONTEXT context = getContext(getFlags);
		del(context);
		setContext(context);
	}

	void closeHandle()
	{
		enforce(CloseHandle(_handle));
		_handle = null;
	}
}
