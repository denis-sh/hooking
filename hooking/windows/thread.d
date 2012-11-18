/** Functions for thread manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.thread;

import hooking.windows.c.winternl;
import core.sys.windows.windows;
import std.exception;


/** This struct encapsulates thread manipulation functionality.
*/
struct Thread
{
	package HANDLE _handle;
	package DWORD _threadId;


	/// Construct a $(D Thread) from a $(D threadHandle).
	this(HANDLE threadHandle)
	out { assert(associated); }
	body
	{
		_handle = threadHandle;
		_threadId = getThreadOrProcessIdOfThread(_handle, false);
	}


	/** Returns whether $(D this) is _associated with a thread.
	It is asserted that no member functions are called for an unassociated
	$(D Thread) struct.

	Example:
	---
	assert(!Thread.init.associated);
	auto h = Thread.init.handle; // assert violation
	---
	*/
	@property bool associated() const @safe pure nothrow
	{ return _handle || _threadId; }

	unittest
	{
		assert(!Thread.init.associated);
	}


	/// Gets the native _handle.
	@property HANDLE handle()
	in { assert(associated); }
	body { return _handle; }


	/// Gets the thread identifier.
	@property DWORD threadId() const
	in { assert(associated); }
	body { return _threadId; }


	/// Gets the process identifier of the owner process.
	@property DWORD ownerProcessId()
	in { assert(associated); }
	body { return enforce(getThreadOrProcessIdOfThread(_handle, true)); }


	/** Suspends thread.

	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms686345(v=vs.85).aspx,
	SuspendThread).
	*/
	void suspend()
	in { assert(associated); }
	body { enforce(SuspendThread(_handle) != -1); }


	/** Resumes thread.

	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms685086(v=vs.85).aspx,
	ResumeThread).
	*/
	void resume()
	in { assert(associated); }
	body { enforce(ResumeThread(_handle) != -1); }


	/** Waits for thread's EIP to be fixed on $(D address) (e.g. because of a `JMP $-2;` loop).

	It will resume the thread if it is suspended and then increase suspended count with the same value.
	*/
	void executeUntil(size_t address)
	in { assert(associated); }
	body
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


	/** Gets thread context.
	
	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms679362(v=vs.85).aspx,
	GetThreadContext).
	*/
	CONTEXT getContext(DWORD flags)
	in { assert(associated); }
	body
	{
		CONTEXT context;
		context.ContextFlags = flags;
		enforce(GetThreadContext(_handle, &context));
		return context;
	}


	/** Sets thread context.

	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms680632(v=vs.85).aspx,
	SetThreadContext).
	*/
	void setContext(CONTEXT context)
	in { assert(associated); }
	body
	{
		enforce(SetThreadContext(_handle, &context));
	}

	
	/// Convenient function for changing thread context.
	void changeContext(DWORD getFlags, scope void delegate(ref CONTEXT) del)
	in { assert(associated); }
	body
	{
		CONTEXT context = getContext(getFlags);
		del(context);
		setContext(context);
	}
}


/** Closes $(D thread) handle if any.
$(D thread) may be unassociated.
*/
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
