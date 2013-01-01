/** WinAPI utils for TLS fixing

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module tlsfixer.winutils;

import core.sys.windows.windows;
import core.stdc.stdlib: malloc, free;

import hooking.windows.c.winternl;

import tlsfixer.ntdll;


T enforceErr(T)(T value, const(char)[] msg = null, string file = __FILE__, size_t line = __LINE__) nothrow
{
	if(!value)
	{
		debug(tlsfixer)
		{
			import core.stdc.stdio: fprintf, stderr; 
			fprintf(stderr, "Error@%s(%u): %s\n",
				file.ptr, line, msg ? msg.ptr : "Enforcement failed");
		}
		assert(0);
	}
	return value;
}


void initWinUtils() nothrow
{
	processHeap = enforceErr(GetProcessHeap());
}


private __gshared HANDLE processHeap;

void* allocateProcessHeap(size_t size, uint flags = 0) nothrow
in { assert(size); }
body
{
	return enforceErr(Ntdll.RtlAllocateHeap(processHeap, flags, size));
}

void freeProcessHeap(void* heapBase) nothrow
in { assert(heapBase); }
body
{
	enforceErr(Ntdll.RtlFreeHeap(processHeap, 0, heapBase));
}


// Based on hooking.windows.process.Process.getThreadIds
DWORD[] getCurrentProcessThreadIds() nothrow
{
	immutable DWORD processId = GetCurrentProcessId();
	auto buff = helperNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemProcessInformation, 0x20000);
	void onScopeExit() nothrow { free(buff.ptr); }

	size_t offset = 0;
	for(;;)
	{
		auto sysProcessInfo = cast(SYSTEM_PROCESS_INFORMATION*) (buff.ptr + offset);

		if(cast(DWORD) sysProcessInfo.UniqueProcessId == processId)
		{
			auto threadIds = (cast(DWORD*) malloc(DWORD.sizeof * sysProcessInfo.NumberOfThreads))
				[0 .. sysProcessInfo.NumberOfThreads];
			auto sysThreadInfo = cast(SYSTEM_THREAD_INFORMATION*) (sysProcessInfo + 1);
			foreach(ref threadId; threadIds)
			{
				assert(cast(DWORD) sysThreadInfo.ClientId.UniqueProcess == processId);
				threadId = cast(DWORD) sysThreadInfo.ClientId.UniqueThread;
				++sysThreadInfo;
			}
			return onScopeExit(), threadIds;
		}

		if(!sysProcessInfo.NextEntryOffset)
			return onScopeExit(), null;
		offset += sysProcessInfo.NextEntryOffset;
	}
}

// Based on hooking.windows.process.helperNtQuerySystemInformation
private void[] helperNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, size_t initialBufferSize) nothrow
{
	size_t buffSize = initialBufferSize;
	for(;;)
	{
		void* buff = malloc(buffSize);
		if(!buff) return null;
		DWORD needed = -1;
		NTSTATUS res = Ntdll.NtQuerySystemInformation(SystemInformationClass,
			buff, buffSize, &needed);
		if(res != STATUS_INFO_LENGTH_MISMATCH)
		{
			if(res < 0) return free(buff), null;
			return buff[0 .. needed];
		}
		free(buff);

		import std.algorithm: max;
		// Possible integer overflow should not be triggered here.
		buffSize = max(needed + 0x2000, buffSize * 2);
	}
}
