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
