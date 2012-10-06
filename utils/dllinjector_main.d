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

import hooking.windows.dllinjector;


void main(string[] args)
{
	immutable(char)[0] invalid;
	string file = invalid, fileArgs, dll = invalid;
	bool wait = false;
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

	launchWithDll(file, fileArgs, dll, wait);
}
