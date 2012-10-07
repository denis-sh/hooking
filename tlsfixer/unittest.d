module dlloader;

import std.c.windows.windows;
import core.thread;
import std.stdio;
import stdd.windows.pe;
import stdd.windows.tlsfixes;

__gshared extern(C) extern int _tls_index, _tlsstart, _tlsend, _tls_callbacks_a;

__gshared HANDLE h;

void main()
{
	enum root = `D:\Denis\Coding\D\Projects\DLLoader\`;
	/*auto h1 = enforce(LoadLibraryA(`DDynamicLibs\Release\CDynamicLib1WithTLS.dll`));
	auto h2 = enforce(LoadLibraryA(`DDynamicLibs\Release\CDynamicLib2WithTLS.dll`));
	FreeLibrary(h1);
	FreeLibrary(h2);*/
	fixLibraryLoading();
	auto clib1 = enforce(LoadLibraryA(root~`DDynamicLibs\Release\CDynamicLib1WithTLS.dll`));
	auto clib2 = enforce(LoadLibraryA(root~`DDynamicLibs\Release\CDynamicLib2WithTLS.dll`));
	FreeLibrary(clib1);
	//h1 = enforce(LoadLibraryA(`DDynamicLibs\Release\CDynamicLib1WithTLS.dll`));
	/*
	FreeLibrary(h1);
	FreeLibrary(h2);
	h1 = enforce(LoadLibraryA(`DDynamicLibs\Release\CDynamicLib1WithTLS.dll`));
	FreeLibrary(h1);*/
	printf("----------------Msg1----------------\n");
	//
	//auto dlib1 = enforce(LoadLibraryA(`libs\DDynamicLib1.dll`));
	//auto dlib2 = enforce(LoadLibraryA(`libs\DDynamicLib2.dll`));
	//void* h = LoadLibraryW(`D:\Denis\Coding\C++\MyDLL\Debug\MyDLL1`w.ptr);
	printf("----------------Msg2----------------\n");
	alias extern(C) int F();
	//writeln("getIntTLSVar: ", (cast(F*)GetProcAddress(h, "getIntTLSVar"))());
//	assert(h);
	writeln("Not started.");
	auto t = new Thread(function {
		writeln("Sarted.");
		//h = enforce(LoadLibraryW(`D:\Denis\Coding\C++\MyDLL\Debug\MyDLL1`w.ptr));
		foreach(i; 0 .. uint.max >> 4) { }
		writeln("Thread.readln"); //readln();
		writeln("Finished.");
	});
	writeln("May be started.");
	writeln("t.start"); //readln();
	t.start();
	writeln("t.join"); //readln();
	t.join();
	//FreeLibrary(h);
	writeln("Sarted.");
	//enforce(LoadLibraryA("d3dim"));
	//readln();


	writeln("End"); //readln();
	//FreeLibrary(dlib1);
	//FreeLibrary(dlib2);
	writeln("End of `main`.");
}