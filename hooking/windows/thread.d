/** Functions for thread manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.thread;

import hooking.windows.c.winternl;
import core.sys.windows.windows;
import std.exception;

/** Returns whether $(D thread) is accosiated with a thread.
It is asserted that no member functions are called for an unassociated
$(D Thread) struct.

Example:
---
assert(!Thread.init.associated);
auto h = Thread.init.handle; // assert violation
---
*/
@property bool associated(in Thread thread) @safe pure nothrow
{ return thread._handle || thread._threadId; }

unittest
{
	assert(!Thread.init.associated);
}


struct Thread
{
	package HANDLE _handle;
	package DWORD _threadId;

	invariant()
	{ assert(this.associated, "Attempting to use unassociated Thread struct"); }


	this(HANDLE threadHandle)
	{
		_handle = threadHandle;
		_threadId = getThreadOrProcessIdOfThread(_handle, false);
	}


	@property HANDLE handle()
	{ return _handle; }

	@property DWORD threadId() const
	{ return _threadId; }

	@property DWORD ownerProcessId()
	{ return enforce(getThreadOrProcessIdOfThread(_handle, true)); }

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
}

void closeHandle(ref Thread thread)
{
	if(thread._handle)
	{
		enforce(CloseHandle(thread._handle));
		thread._handle = null;
	}
}


// WinAPI helpers
// --------------------------------------------------

DWORD getThreadOrProcessIdOfThread(HANDLE threadHandle, bool returnProcessId) nothrow
{
	if(cast(ubyte) GetVersion() >= 6)
	{
		// GetThreadId and GetProcessIdOfThread present since Windows Vista
		alias extern(Windows) nothrow DWORD function(HANDLE Thread) Type;
		if(returnProcessId)
		{
			static Type GetProcessIdOfThread;
			if(!GetProcessIdOfThread)
			{
				GetProcessIdOfThread = cast(Type) GetProcAddress(LoadLibraryA("kernel32"), "GetProcessIdOfThread");
				assert(GetProcessIdOfThread);
			}
			return GetProcessIdOfThread(threadHandle);
		}
		else
		{
			static Type GetThreadId;
			if(!GetThreadId)
			{
				GetThreadId = cast(Type) GetProcAddress(LoadLibraryA("kernel32"), "GetThreadId");
				assert(GetThreadId);
			}
			return GetThreadId(threadHandle);
		}
	}
	else
	{
		auto NtQueryInformationThread = cast(NtQueryInformationThread)
			GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationThread");
		assert(NtQueryInformationThread);

		THREAD_BASIC_INFORMATION tbi;
		ULONG returnLength;
		if(NtQueryInformationThread(threadHandle, 0 /* THREADINFOCLASS.ThreadBasicInformation */, &tbi, tbi.sizeof, &returnLength) < 0)
			return 0;
		assert(returnLength == tbi.sizeof);
		return cast(DWORD) (returnProcessId ? tbi.ClientId.UniqueProcess : tbi.ClientId.UniqueThread);
	}
}
