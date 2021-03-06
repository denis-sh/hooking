/** DLLInjector util main

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module utils.dllinjector_main;

import std.getopt;
import std.exception;
import std.string: format;
import std.range: empty;
import std.stdio: stderr;
import std.conv: emplace;

import hooking.windows.thread;
import hooking.windows.process;
import hooking.windows.processstartinfo;

enum ExitCodes { success, processNonZeroReturn, dllLoadingFailure, processLaunchingFailure, incorrectUsage }

int main(string[] args)
{
	bool wait = false;
	try
	{
		getopt(args,
			"wait|w", &wait);

		enforce(args.length > 1, "Not enough arguments: no DLL or executable file specified");
		enforce(args.length > 2, "Not enough arguments: no executable file specified");
	}
	catch(Exception e)
	{
		stderr.writefln("%s\nUsage: dllinj [-w|--wait] [--] <dll file> <exe file> [<args>]", e.msg);
		return ExitCodes.incorrectUsage;
	}

	auto dll = args[1], file = args[2], fileArgs = args[2 .. $]; 

	Process process = void;
	const processStartInfo = ProcessStartInfo(file, fileArgs, false, true);
	Thread primaryThread = Thread.init;
	if(auto e = collectException(emplace(&process, processStartInfo, primaryThread)))
	{
		stderr.writefln("Process launching failure: %s", e.msg);
		return ExitCodes.processLaunchingFailure;
	}

	process.initializeWindowsStuff(primaryThread);

	if(auto e = collectException(process.loadDll(primaryThread, dll)))
	{
		stderr.writefln("DLL loading failure: %s", e.msg);
		return ExitCodes.dllLoadingFailure; // FIXME or other failure?
	}

	primaryThread.resume();

	if(wait)
		if(int exitCode = process.waitForExit())
		{
			stderr.writefln("Process returned error code %s", exitCode);
			return ExitCodes.processNonZeroReturn;
		}
	return ExitCodes.success;
}
