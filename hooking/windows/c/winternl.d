/** Functions for process manipulation

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.c.winternl;

import core.sys.windows.windows;


extern(Windows) nothrow:


// Defined in ntstatus.h
alias LONG NTSTATUS;

// Defined in ntstatus.h
enum : NTSTATUS
{
	STATUS_INFO_LENGTH_MISMATCH = 0xc0000004,
}


struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
}


// Not defined in winternl.h
// From http://msdn.microsoft.com/en-us/library/gg750647(prot.20).aspx
struct CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
}


alias NTSTATUS function(
	HANDLE ProcessHandle,
	int /* PROCESSINFOCLASS */ ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
) NtQueryInformationProcess;


enum SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5,
}

alias NTSTATUS function(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
) NtQuerySystemInformation;

// NumberOfThreads from http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/System%20Information/Structures/SYSTEM_PROCESS_INFORMATION.html
struct SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[52 - ULONG.sizeof];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
}

// Not defined in winternl.h
// From http://msdn.microsoft.com/en-us/library/gg750724(prot.20).aspx
struct SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	LONG Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
}
