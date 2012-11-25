/** Functions for thread manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.thread;

import hooking.windows.c.winternl;
import hooking.windows.process: currentWOW64;
import core.sys.windows.windows;
import std.exception;
import std.string;

/** This struct encapsulates thread manipulation functionality.
*/
struct Thread
{
	package
	{
		HANDLE _handle;
		DWORD _handleAccess;
		DWORD _threadId;
	}


	private void checkAccess(DWORD requiredAccess, string func)
	{
		if(cast(ubyte) GetVersion() < 6 && (requiredAccess & THREAD_QUERY_LIMITED_INFORMATION))
			requiredAccess = requiredAccess & ~THREAD_QUERY_LIMITED_INFORMATION | THREAD_QUERY_INFORMATION;
		enforce((_handleAccess & requiredAccess) == requiredAccess,
			xformat("Insufficient thread handle access to call '%s'", func));
	}


	@disable this();
	@disable this(this);


	/** Construct a $(D Thread) from a $(D threadId).
	If $(D tryUsePseudoHandle) is $(D true) and $(D threadId)
	is current thread id then pseudo handle with $(D THREAD_ALL_ACCESS)
	access will be used.
	Otherwise if $(D desiredAccess) is non-zero then a thread handle
	will be opened with requested access.
	Otherwise no handle is opened.
	In the latter case for each member function with "Required handle access"
	paragraph in documentation call a temporary handle with required access is
	opened.
	*/
	this(DWORD threadId, DWORD desiredAccess, bool tryUsePseudoHandle)
	out { assert(associated); }
	body
	{
		if(tryUsePseudoHandle && threadId == GetCurrentThreadId())
		{
			_handle = GetCurrentThread();
			_handleAccess = THREAD_ALL_ACCESS;
		}
		else if(desiredAccess)
		{
			_handle = enforce(OpenThread(desiredAccess, TRUE /* bInheritHandle */, threadId));
			_handleAccess = desiredAccess;
		}
		_threadId = threadId;
	}

	unittest
	{
		assert(Thread(GetCurrentThreadId(), 0, true).handle == GetCurrentThread());
		assert(!Thread(GetCurrentThreadId(), 0, false).handle);
	}


	/** Construct a $(D Thread) from a $(D threadHandle).
	$(D threadHandle) access obtained when it was opened
	should be passed as $(D handleAccess) parameter.
	If $(D remainPseudoHandle) is $(D false) and $(D threadHandle)
	is pseudo handle of current thread then "real" handle with
	access from $(D handleAccess) will be opened instead.
	If $(D remainPseudoHandle) is $(D true) and $(D threadHandle)
	is pseudo handle then $(D handleAccess) will be set to $(D THREAD_ALL_ACCESS).

	$(D threadId) will not be set iff resulting $(D handleAccess)
	doesn't include $(D THREAD_QUERY_INFORMATION) or $(D THREAD_QUERY_LIMITED_INFORMATION).
	In this case calling $(D closeHandle) will result in unassociation of this struct.
	*/
	this(HANDLE threadHandle, DWORD handleAccess, bool remainPseudoHandle)
	out { assert(associated); }
	body
	{
		immutable bool isPseudoHandle = threadHandle == GetCurrentThread();
		if(!remainPseudoHandle && isPseudoHandle)
			this = Thread(GetCurrentThreadId(), handleAccess, false);
		else
		{
			_handle = threadHandle;
			_handleAccess = isPseudoHandle ? THREAD_ALL_ACCESS : handleAccess;
			if(_handleAccess & (THREAD_QUERY_INFORMATION  | THREAD_QUERY_LIMITED_INFORMATION))
				_threadId = enforce(getThreadOrProcessIdOfThread(threadHandle, false));
		}
	}

	unittest
	{
		auto t = Thread(GetCurrentThreadId(), 0, false);
		assert(!t.handle && !t.handleAccess);
		import hooking.windows.process;
		assert(t.ownerProcessId == Process.currentLocal().processId);
	}


	~this()
	{
		if(associated)
			closeHandle();
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


	/// Gets access to the $(D handle).
	@property DWORD handleAccess() const
	in { assert(associated); }
	body { return _handleAccess; }


	/// Gets the thread identifier.
	@property DWORD threadId() const
	in { assert(associated); }
	body { return _threadId; }


	/** Gets the process identifier of the owner process.

	Required handle access:
	$(D THREAD_QUERY_LIMITED_INFORMATION)
	*/
	@property DWORD ownerProcessId()
	in { assert(associated); }
	body
	{
		mixin(requireAccess(q{THREAD_QUERY_LIMITED_INFORMATION}, q{ownerProcessId}));
		return enforce(getThreadOrProcessIdOfThread(_handle, true));
	}


	/** Suspends thread.

	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms686345(v=vs.85).aspx,
	SuspendThread).

	Required handle access:
	$(D THREAD_SUSPEND_RESUME)
	*/
	void suspend()
	in { assert(associated); }
	body
	{
		mixin(requireAccess(q{THREAD_SUSPEND_RESUME}, q{suspend()}));
		enforce(SuspendThread(_handle) != -1);
	}


	/** Resumes thread.

	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms685086(v=vs.85).aspx,
	ResumeThread).

	Required handle access:
	$(D THREAD_SUSPEND_RESUME)
	*/
	void resume()
	in { assert(associated); }
	body 
	{
		mixin(requireAccess(q{THREAD_SUSPEND_RESUME}, q{resume()}));
		enforce(ResumeThread(_handle) != -1);
	}


	/** Waits for thread's EIP to be fixed on $(D address) (e.g. because of a `JMP $-2;` loop).

	It will resume the thread if it is suspended and then increase suspended count with the same value.

	Required handle access:
	$(D THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT), on WOW64 $(D THREAD_QUERY_INFORMATION) is also required.
	*/
	void executeUntil(size_t address)
	in { assert(associated); }
	body
	{
		mixin(requireAccess(q{THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | (currentWOW64 ? THREAD_QUERY_INFORMATION : 0)}, q{executeUntil(address)}));
		DWORD suspendCount = ResumeThread(_handle);
		enforce(suspendCount != -1);
		foreach(i; 1 .. suspendCount)
			resume();

		for(size_t i = 0; ;++i)
		{
			Sleep(20);
			if(getContext(CONTEXT_CONTROL).Eip == address)
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

	Required handle access:
	$(D THREAD_GET_CONTEXT), on WOW64 $(D THREAD_QUERY_INFORMATION) is also required.
	*/
	CONTEXT getContext(DWORD flags)
	in { assert(associated); }
	body
	{
		mixin(requireAccess(q{THREAD_GET_CONTEXT | (currentWOW64 ? THREAD_QUERY_INFORMATION : 0)}, q{getContext(flags)}));
		CONTEXT context;
		context.ContextFlags = flags;
		enforce(GetThreadContext(_handle, &context));
		return context;
	}


	/** Sets thread context.

	Calls
	$(HTTP msdn.microsoft.com/en-us/library/windows/desktop/ms680632(v=vs.85).aspx,
	SetThreadContext).

	Required handle access:
	$(D THREAD_SET_CONTEXT)
	*/
	void setContext(CONTEXT context)
	in { assert(associated); }
	body
	{
		mixin(requireAccess(q{THREAD_SET_CONTEXT}, "setContext(context)"));
		enforce(SetThreadContext(_handle, &context));
	}

	
	/** Convenient function for changing thread context.

	Required handle access:
	$(D THREAD_GET_CONTEXT | THREAD_SET_CONTEXT), on WOW64 $(D THREAD_QUERY_INFORMATION) is also required.
	*/
	void changeContext(DWORD getFlags, scope void delegate(ref CONTEXT) del)
	in { assert(associated); }
	body
	{
		mixin(requireAccess(q{THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | (currentWOW64 ? THREAD_QUERY_INFORMATION : 0)}, "changeContext(getFlags, del)"));
		CONTEXT context = getContext(getFlags);
		del(context);
		setContext(context);
	}


	/** Closes native handle if any.
	*/
	void closeHandle()
	in { assert(associated); }
	body
	{
		if(_handle && _handle != GetCurrentThread())
		{
			enforce(CloseHandle(_handle));
			_handle = null;
		}
	}
}


enum : DWORD
{
	THREAD_TERMINATE                 = 0x0001,  
	THREAD_SUSPEND_RESUME            = 0x0002,  
	THREAD_GET_CONTEXT               = 0x0008,  
	THREAD_SET_CONTEXT               = 0x0010,  
	THREAD_QUERY_INFORMATION         = 0x0040,  
	THREAD_SET_INFORMATION           = 0x0020,  
	THREAD_SET_THREAD_TOKEN          = 0x0080,
	THREAD_IMPERSONATE               = 0x0100,
	THREAD_DIRECT_IMPERSONATION      = 0x0200,

	THREAD_SET_LIMITED_INFORMATION   = 0x0400,
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800,

	THREAD_ALL_ACCESS        = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF
}


private string requireAccess(string requiredAccess, string func)
{
	return xformat(q{
		if(_handle) checkAccess(%s, q{%s});
		else return Thread(_threadId, %1$s, true).%2$s;
	}, requiredAccess, func);
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


// WinAPI
// --------------------------------------------------

extern(Windows) nothrow
{
    extern HANDLE OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
}
