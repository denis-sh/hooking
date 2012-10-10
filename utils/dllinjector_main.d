/** DLLInjector util main

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module utils.dllinjector_main;

import std.getopt;
import std.exception;
import std.string: xformat;
import std.range: empty;
import std.stdio: stderr;

import hooking.windows.process;

enum ExitCodes { success, processNonZeroReturn, dllLoadingFailure, processLaunchingFailure, incorrectUsage }

int main(string[] args)
{
	immutable(char)[0] invalid;
	string file = invalid, fileArgs, dll = invalid;
	bool wait = false;
	try
	{
		getopt(args,
			"file|f", &file,
			"args|a", &fileArgs,
			"dll|d", &dll,
			"wait|w", &wait);

		enforce(file !is invalid, "Invalid arguments: `file` not specified");
		enforce(dll !is invalid , "Invalid arguments: `dll` not specified");
		enforce(!file.empty     , "Invalid arguments: `file` is empty");
		enforce(!dll.empty      , "Invalid arguments: `dll` is empty");
		enforce(args.length == 1, xformat("Superfluous arguments: %s", args));
	}
	catch(Exception e)
	{
		stderr.writefln("Incorrect usage: %s", e.msg);
		return ExitCodes.incorrectUsage;
	}


	Process process;
	if(auto e = collectException(process = Process(file, fileArgs, true)))
	{
		stderr.writefln("Process launching failure: %s", e.msg);
		return ExitCodes.processLaunchingFailure;
	}
	scope(exit) process.closeHandles();

	process.initializeWindowsStuff();

	if(auto e = collectException(process.loadDll(dll)))
	{
		stderr.writefln("DLL loading failure: %s", e.msg);
		return ExitCodes.dllLoadingFailure; // FIXME or other failure?
	}

	process.primaryThread.resume();

	if(wait)
		if(int exitCode = process.waitForExit())
		{
			stderr.writefln("Process returned error code %s", exitCode);
			return ExitCodes.processNonZeroReturn;
		}
	return ExitCodes.success;
}
