/** Information for starting a process.

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.processstartinfo;

import core.sys.windows.windows;
import std.algorithm;
import std.array;
import std.conv;
import std.exception;
import std.path;
import std.string;
import std.utf;


/// This struct encapsulates process starting information.
struct ProcessStartInfo
{
	private
	{
		string _commandLine, _file;
		string[] _args;
		bool _search, _suspended, _newConsole;
	}

	@property
	{
		/** Returns whether $(D ProcessStartInfo) is _associated with a file.

		E.g. $(D ProcessStartInfo.init) is unassociated.
		*/
		bool associated() const
		{ return storedAsCommandLine || _file; }

		unittest
		{
			assert(!ProcessStartInfo.init.associated);
			assert( ProcessStartInfo("a").associated);
			assert( ProcessStartInfo("a", null).associated);
		}


		/** Returns whether $(D ProcessStartInfo) is stored as a command line.

		It is $(D false) for an unassociated $(D ProcessStartInfo).
		*/
		bool storedAsCommandLine() const
		{ return !!_commandLine; }

		unittest
		{
			ProcessStartInfo p;
			assert(!p.storedAsCommandLine);

			p = ProcessStartInfo("a");
			assert( p.storedAsCommandLine);

			p.file = "a";
			assert(!p.storedAsCommandLine);

			p = ProcessStartInfo("a", null);
			assert(!p.storedAsCommandLine);

			p.commandLine = "a";
			assert( p.storedAsCommandLine);

			p.arguments = null;
			assert(!p.storedAsCommandLine);
		}


		/** Gets executable file & arguments as a command line.

		Returns $(D null) if unassociated.

		Note:
		File path is always quoted.
		*/
		string commandLine() const
		{
			if(!associated)
				return null;
			if(storedAsCommandLine)
				return _commandLine;

			import std.process;
			return format(`"%s"%-( %s%)`, _file, _args.map!(arg => escapeWindowsArgument(arg))());
		}


		/** Sets executable file & arguments as command line.

		Also sets $(D storedAsCommandLine).

		Note:
		File path will be quoted if it isn't.

		Preconditions:
		$(D value) starts from a valid path.
		*/
		void commandLine(string value)
		in { assert(value.divideCommandLine()[0].isValidPath()); }
		body
		{
			_commandLine = value.strip();
			if(_commandLine[0] != '"')
			{
				immutable t = value.divideCommandLine();
				_commandLine = '"' ~ t[0] ~ '"';
				if(t[1].length)
					_commandLine ~= ' ' ~ t[1];
			}
		}


		/** Gets path to executable _file.

		Returns $(D null) if unassociated.
		*/
		string file() const
		{
			if(storedAsCommandLine)
				return _commandLine.divideCommandLine()[0];
			return _file;
		}


		/** Sets path to executable _file.

		Also unsets $(D storedAsCommandLine).

		Preconditions:
		$(D value) is a valid path.
		*/
		void file(string value)
		in { assert(value.isValidPath()); }
		body
		{
			if(storedAsCommandLine)
			{
				// can't use `this.arguments` here because it's `const(string)[]`
				_args = extractCommandLineArguments(_commandLine);
				_commandLine = null;
			}
			_file = value;
		}


		/** Gets _arguments.

		Returns $(D null) if unassociated.
		*/
		const(string)[] arguments() const
		{
			if(storedAsCommandLine)
				return extractCommandLineArguments(_commandLine);
			return _args;
		}


		/** Sets _arguments.

		Also unsets $(D storedAsCommandLine).
		*/
		void arguments(string[] value)
		{
			if(storedAsCommandLine)
			{
				_file = file;
				_commandLine = null;
			}
			_args = value;
		}


		// commandLine, file, and arguments unittests
		unittest
		{
			assert(!ProcessStartInfo.init.commandLine);
			assert(!ProcessStartInfo.init.file);
			assert(!ProcessStartInfo.init.arguments);
			void test(string fromCmd, string toCmd, string toFile, string[] toArgs)
			{
				auto p = ProcessStartInfo();
				p.commandLine = fromCmd;
				assert(p.commandLine == toCmd ? toCmd : fromCmd);
				assert(p.file == toFile);
				assert(p.arguments == toArgs);
			}
			test(`a`    , `"a"`, `a`, []);
			test(`"a"`  , `"a"`, `a`, []);
			test(` a `  , `"a"`, `a`, []);
			test(` "a" `, `"a"`, `a`, []);
			test(` a   b  c `, `"a" b  c`    , `a`, [`b`, `c`]);
			test(` "a"   b  c `, `"a"   b  c`, `a`, [`b`, `c`]);
			test(`"a" "b c" "d e\ " "f` , null, `a`, [`b c`, `d e\ `, `f`]);
			test(`"a" "b c" "d e\" "f`  , null, `a`, [`b c`, `d e" f`]    );
			test(`"a" "" """ """" """""`, null, `a`, [``, `"`, `" ""`]);
		}

		unittest
		{
			assert(!ProcessStartInfo.init.file);
			void test(string fromFile, string toFile, string toCmd, string[] fromArgs, string toCmdWithArgs)
			{
				auto p = ProcessStartInfo();
				p.file = fromFile;
				assert(p.file == toFile);
				assert(p.commandLine == toCmd);
				p.arguments = fromArgs;
				assert(p.commandLine == toCmdWithArgs, format("\n%s != \n%s", p.commandLine, toCmdWithArgs));
			}
			test(`a`    , `a`    , `"a"`    , [], `"a"`);
			test(`a`    , `a`    , `"a"`    , [`b`], `"a" "b"`);
			test(`a\b`  , `a\b`  , `"a\b"`  , [``], `"a\b" ""`);
			test(`a\b c`, `a\b c`, `"a\b c"`, [`d`, `"e`, `\f`, `\"g`], `"a\b c" "d" "\"e" "\f" "\\\"g"`);
		}


		/** Whether OS will search for executable file.

		Note:
		Be careful with this as it can lead to $(B security vulnerability) if used careless.

		Default value is $(D false).
		*/
		ref inout(bool) searchForFile() inout
		{ return _search; }

		unittest
		{
			assert(!ProcessStartInfo.init.searchForFile);
			auto p = ProcessStartInfo("a");
			assert(!p.searchForFile);
			assert( p.searchForFile |= true);
			assert( ProcessStartInfo("a", true ).searchForFile);
			assert( ProcessStartInfo("a", null, true).searchForFile);
		}


		/** Whether the primary thread will be
		created in a _suspended state.

		The primary thread of the new process will not run until
		it will be resumed.

		Default value is $(D false).
		*/
		ref inout(bool) suspended() inout
		{ return _suspended; }

		unittest
		{
			assert(!ProcessStartInfo.init.suspended);
			auto p = ProcessStartInfo("a");
			assert(!p.suspended);
			assert( p.suspended |= true);
			assert( ProcessStartInfo("a", false, true).suspended);
			assert( ProcessStartInfo("a", null, false, true).suspended);
		}


		/** Whether new console will be created.

		If not set, parent's console will be inherited.

		Default value is $(D false).
		*/
		ref inout(bool) createNewConsole() inout
		{ return _newConsole; }

		unittest
		{
			assert(!ProcessStartInfo.init.createNewConsole);
			auto p = ProcessStartInfo("a");
			assert(!p.createNewConsole);
			assert( p.createNewConsole |= true);
			assert( ProcessStartInfo("a", false, false, true).createNewConsole);
			assert( ProcessStartInfo("a", null, false, false, true).createNewConsole);
		}
	}


	/// Construct a $(D ProcessStartInfo) from a $(D commandLine).
	this(string commandLine, bool searchForFile = false, bool suspended = false, bool createNewConsole = false)
	{
		this.commandLine = commandLine;
		this.searchForFile = searchForFile;
		this.suspended = suspended;
		this.createNewConsole = createNewConsole;
	}


	/// Construct a $(D ProcessStartInfo) from an executable $(D file) and $(D arguments).
	this(string file, string[] arguments, bool searchForFile = false, bool suspended = false, bool createNewConsole = false)
	{
		this.file = file;
		this.arguments = arguments;
		this.searchForFile = searchForFile;
		this.suspended = suspended;
		this.createNewConsole = createNewConsole;
	}
}


private:

string[2] divideCommandLine(string commandLine)
{
	commandLine = commandLine.strip();
	immutable quoted = commandLine.skipOver('"');
	immutable r = commandLine.findSplit(quoted ? `"` : " ");
	return [r[0], r[2].stripLeft()];
}

string[] extractCommandLineArguments(string commandLine)
{
	int numArgs;
	LPWSTR* argsW = enforce(CommandLineToArgvW(toUTF16z(commandLine), &numArgs));
	scope(exit) LocalFree(argsW);
	return argsW[1 .. numArgs].map!(a => fromUTF16z(a))().array();
}

string fromUTF16z(in wchar* wstr)
{
	import core.stdc.wchar_;
	return to!string(wstr[0 .. wcslen(wstr)]);
}


// WinAPI
// --------------------------------------------------

extern(Windows) nothrow
{
	extern LPWSTR* CommandLineToArgvW(LPCWSTR lpCmdLine, int *pNumArgs);
	alias HANDLE HLOCAL;
	extern HLOCAL LocalFree(HLOCAL hMem);
}
