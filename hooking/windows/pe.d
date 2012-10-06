/** Functions for working with Portable Executable (PE) format

Copyright: Denis Shelomovskij 2012

License: $(WEB boost.org/LICENSE_1_0.txt, Boost License 1.0).

Authors: Denis Shelomovskij
*/
module hooking.windows.pe;

import std.c.windows.windows;
import core.sys.windows.dll;
import core.sys.windows.threadaux;

import std.c.string: strlen;
import std.algorithm: until, map, filter, cmp;
import std.range: take, array, assumeSorted;
import std.exception: enforce;
version(unittest) import std.algorithm: canFind, find, equal;

import std.string: format;

debug import std.stdio;
debug import std.conv: to;
else import std.conv: to; //FIXME ? TODO

// TODO Can sequence be used instead?
private mixin template DummyRandomAccessRange() {
	private size_t index, count;

	@property empty() const
	{ return index == count; }
	
	@property front()
	{ assert(!empty); return opIndex(index); }
	
	void popFront()
	{ assert(!empty); ++index; }
	
	@property back()
	{ assert(!empty); return opIndex(count - 1); }
	
	void popBack()
	{ assert(!empty); --count; }
	
	@property save()
	{ return this; }
	
	auto opSlice()
	{ return this; }

	auto opSlice(size_t lower, size_t upper)
	{
		assert(upper >= lower && upper <= count);

		auto ret = this;
		ret.index += lower;
		ret.count = upper - lower + ret.index;
		return ret;
	}

	@property size_t length() const
	{ return count - index; }

	alias length opDollar;
}

// TODO: Use RtlImage*, e.g. RtlImageDirectoryEntryToData?
struct PEFile {
	/// Here is IMAGE_DOS_HEADER
	const(void)* base;
	bool loaded;

	this(const(void)* handle, bool loaded) nothrow {
		this.loaded = loaded;

		// handle is a base address except it can contain some flags.
		// Base address is 64 KiB aligned so just clear last 2 bytes
		base = cast(const(void)*) (cast(size_t) handle & ~0xFFFF);
	}

	void validate() {
		// Test WORD e_magic (offset = 0) == IMAGE_DOS_SIGNATURE
		enforce(*cast(char[2]*) base == "MZ", "Invalid DOS header (first 2 bytes != 'MZ').");

		auto ntH = imageNtHeaders;
		enforce(*cast(char[4]*) ntH == "PE\0\0",
			*cast(char[2]*) ntH == "NE" ? "Invalid PE header: it is NE (16 bit) file." :
			"Invalid PE header.");

		enforce(ntH.FileHeader.Machine == 0x014c, // IMAGE_FILE_MACHINE_I386
			ntH.FileHeader.Machine == 0x8664 ? // IMAGE_FILE_MACHINE_AMD64
			"x64 PE file isn't supported." :
			ntH.FileHeader.Machine == 0x0200 ? // IMAGE_FILE_MACHINE_IA64
			"Intel Itanium PE file isn't supported." :
			"Invalid FileHeader.Machine."); 

		enforce(ntH.OptionalHeader.Magic == 0x10b, // IMAGE_NT_OPTIONAL_HDR32_MAGIC
			"Invalid OptionalHeader.Magic.");
		
		// Looks like maximum number of sections that PE loader supports
		// is 0x60 for Windows XP and 0xFFFF for Windows Vista and later.
		enforce(ntH.FileHeader.NumberOfSections, "NumberOfSections is zero."); 
		
		// TODO do we support IMAGE_SUBSYSTEM_NATIVE (device drivers and native system processes)? 
		enforce(ntH.OptionalHeader.Subsystem == 1 || // IMAGE_SUBSYSTEM_NATIVE
			ntH.OptionalHeader.Subsystem == 2 || // IMAGE_SUBSYSTEM_WINDOWS_GUI
			ntH.OptionalHeader.Subsystem == 3, // IMAGE_SUBSYSTEM_WINDOWS_CUI
			format("Unsupported OptionalHeader.Subsystem %s: it isn't Windows GUI or CUI subsystem.",
				ntH.OptionalHeader.Subsystem));
	
		// TODO check Characteristics? enforce(ntH.FileHeader.Characteristics & (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL));
	}

	@property imageNtHeaders() const nothrow {
		// get LONG e_lfanew (offset = 60) as DWORD (Note: have to converto to DWORD)
		immutable toNt = *cast(DWORD*) (base + 60);
		return cast(const(IMAGE_NT_HEADERS)*) (base + toNt);
	}

	@property const(IMAGE_SECTION_HEADER)[] imageSectionHeaders() const nothrow
	out(res) {
		const ntH = imageNtHeaders;
		assert(res[0].VirtualAddress ==
			alignUp(ntH.OptionalHeader.SizeOfHeaders, ntH.OptionalHeader.SectionAlignment));
	}
	body {
		const ntH = imageNtHeaders;
		return (cast(const(IMAGE_SECTION_HEADER)*)(cast(DWORD) ntH +
			DWORD.sizeof + IMAGE_FILE_HEADER.sizeof + ntH.FileHeader.SizeOfOptionalHeader)
			)[0 .. ntH.FileHeader.NumberOfSections]; 
	}

	/// Relative virtual address to process memory pointer
	const(void)* rvaToPtr(in DWORD rva) const nothrow
	{
		if(loaded)
			return cast(const(void)*) (base + rva);
		const ntH = imageNtHeaders;
		auto shArr = imageSectionHeaders;
		
		if(rva < shArr[0].VirtualAddress)
			return base + rva; // rva doesn't belong to a section

		const(void)* ptr = null;
		int inSections = 0;
		foreach(sh; shArr)
		{
			DWORD size = sh.SizeOfRawData; 	
			
			if(sh.Misc.VirtualSize < sh.SizeOfRawData && sh.Misc.VirtualSize
			   || !sh.SizeOfRawData)	//будем юзать самый минимальный ненулевой размер; 
			{
				size = sh.Misc.VirtualSize;
			}
	 
			if(rva >= sh.VirtualAddress && rva < sh.VirtualAddress + size)		//если мы нашли секцию, в которую указывает этот самый rva, 
			{
				++inSections;
				//ЁБА! физический адрес секции выравнивается на нижнюю границу! 
				ptr = cast(const(void)*)(cast(DWORD) base + rva - sh.VirtualAddress +
					alignUown(sh.PointerToRawData, ntH.OptionalHeader.FileAlignment));	//тогда найдем оффсет и прибавим базу мэппинга . получится абсолютный адрес в памяти; 
			}
		}
		assert(inSections <= 1);
		return ptr;
	}

	private const(void)* getImageDirectoryEntry(size_t index, void function(size_t size) nothrow testSize = null) const nothrow {
		const ntH = imageNtHeaders;
		const tlsEntry = ntH.OptionalHeader.DataDirectory[index];
		if(!tlsEntry.VirtualAddress)
			return null;
		if(testSize) testSize(tlsEntry.Size);
		return rvaToPtr(tlsEntry.VirtualAddress);
	}

	@property imageTlsDirectory() const nothrow {
		// IMAGE_DIRECTORY_ENTRY_TLS = 9
		return cast(const(IMAGE_TLS_DIRECTORY)*)
			getImageDirectoryEntry(9, (size) { assert(size == IMAGE_TLS_DIRECTORY.sizeof); });
	}

	@property imageExportDirectory() const nothrow {
		// IMAGE_DIRECTORY_ENTRY_EXPORT = 0
		return cast(const(IMAGE_EXPORT_DIRECTORY)*) getImageDirectoryEntry(0);
	}

	@property exportedFunctionsByName() const {
		static struct ExportedFunction {
			const(char)[] name;
			const(void)* address;
			DWORD index, rvaAddress;

			int opCmp(in ExportedFunction o) const {
				return cmp(cast(const(ubyte[])) name, cast(const(ubyte[])) o.name);
			}

			int opCmp(in string o) const {
				return cmp(cast(const(ubyte[])) name, cast(const(ubyte[])) o);
			}
		}
		
		static struct Result
		{
			mixin DummyRandomAccessRange;

			private {
				PEFile pe;
				const(DWORD)* names, addresses;
				const(WORD)* indexes;
			}
			
			ExportedFunction opIndex(size_t n)
			in { assert(n < count); }
			body {
				const namePtr = cast(const(char*)) pe.rvaToPtr(names[n]);
				// Note: in some papers IMAGE_EXPORT_DIRECTORY.Base is
				// substracted from n but is isn't how PE works.
				immutable index = indexes[n];
				immutable rva = addresses[index];
				return ExportedFunction(namePtr[0 .. strlen(namePtr)],
					pe.rvaToPtr(rva),
					index, rva);
			}
		}

		if(auto dir = imageExportDirectory)
			return assumeSorted(Result(0, dir.NumberOfNames, this,
				cast(const(DWORD)*) rvaToPtr(dir.AddressOfNames),
				cast(const(DWORD)*) rvaToPtr(dir.AddressOfFunctions),
				cast(const(WORD)*) rvaToPtr(dir.AddressOfNameOrdinals)));
		return assumeSorted(Result(0, 0));
	}

	/*@property exportedFunctionsByAddress() const {
		static struct Result
		{
			mixin DummyRandomAccessRange;

			private {
				PEFile pe;
				const(DWORD)* addresses;
			}
			
			const(void)* opIndex(size_t n)
			{
				assert(n < count);
				return pe.rvaToPtr(addresses[n]);
			}
		}

		if(auto dir = imageExportDirectory)
			return Result(0, dir.NumberOfFunctions, this,
				cast(const(DWORD)*) rvaToPtr(dir.AddressOfFunctions));
		return Result(0, 0);
	}*/

	@property exportedFunctions() const {
		static struct Result {
			const(void)* address;
			const(char)[] name;
			const(char)[][] names; // Is it possible/legal to have multiple names?
		}

		if(auto dir = imageExportDirectory) {
			// auto res = exportedFunctionsByAddress.map!(a => Result(a))();
			if(dir.NumberOfFunctions == 5) {
				auto arr = (cast(const(DWORD)*) rvaToPtr(dir.AddressOfFunctions))
					[0 .. dir.NumberOfFunctions];

				auto rva = arr[1];
				auto t2 = Result(rvaToPtr(rva));
				foreach(i, t; arr) {
					if(i==1)continue;
					auto t3 = Result(rvaToPtr(t));
				}
			}
			auto res = (cast(const(DWORD)*) rvaToPtr(dir.AddressOfFunctions))
				[0 .. dir.NumberOfFunctions]
				.map!(a => Result(rvaToPtr(a)))()
				.array();
			foreach(named; exportedFunctionsByName) {
				assert(named.address == res[named.index].address);
				auto t = &res[named.index];
				t.name = !t.names ? named.name : null;
				t.names ~= named.name;
			}
			return res;
		}
		return null;
	}

	@property string[] imports() const
	{
		const ntH = imageNtHeaders;

		// IMAGE_DIRECTORY_ENTRY_IMPORT = 1
		immutable DWORD impRva = ntH.OptionalHeader.DataDirectory[1].VirtualAddress;	//x; 
		/*immutable*/ DWORD impSize = ntH.OptionalHeader.DataDirectory[1].Size;
		if(impSize % IMAGE_IMPORT_DESCRIPTOR.sizeof) // TODO when?
			impSize = (impSize / IMAGE_IMPORT_DESCRIPTOR.sizeof) * IMAGE_IMPORT_DESCRIPTOR.sizeof;
		assert(impSize % IMAGE_IMPORT_DESCRIPTOR.sizeof == 0);

		if(!impRva || !impSize)
			return null; // no import table

		if(const void* offset = rvaToPtr(impRva))
			return (cast(IMAGE_IMPORT_DESCRIPTOR[]) offset[0 .. impSize])
				.until!`!a.OriginalFirstThunk && !a.FirstThunk`()
				.filter!(imId => imId.Name)()
				.map!(imId => to!string(cast(const(char)*) rvaToPtr(imId.Name)))()
				.array(); // TODO return range

		return null;
	}
}

/*void printPeInfo(in PEFile pe) {
	writefln("imports: %s", pe.imports);
	writefln("exportes: names=%s, funcs=%s",
			 pe.exportedFunctionsByName.length,
			 pe.exportedFunctions.length);
	writefln("exported by name:\n%(\t%s\n%)",
			 pe.exportedFunctionsByName.take(3).map!(a=>format("%s %s %s %X", a.tupleof))());

	auto em = pe.exportedFunctions.filter!`a.names.length >= 2`();
	import std.range;
	writefln("exported multinamed: %s\n%(\t%s\n%)", walkLength(em), em.take(3).map!(a=>format("%X %s", a.tupleof))());

	auto eu = pe.exportedFunctions.filter!`a.names.empty`();
	import std.range;
	writefln("exported unnamed: %s\n%(\t%s\n%)", walkLength(eu), eu.take(3).map!(a=>format("%X %s", a.tupleof))());
}*/

unittest {
	void test(string name, string exportedName, string[] imports) {
		void testPe(in PEFile pe) {
			assert(!pe.imageTlsDirectory);
			assert(pe.exportedFunctionsByName.contains(exportedName));
			static string t; t = exportedName; // dmd @@@BUG@@@ workaround
			assert(pe.exportedFunctions.canFind!(a => a.name == t)());
			assert(equal(pe.imports, imports));
		}

		{
			void* pExe;
			{
				import std.process;
				HANDLE hFile = CreateFileA((environment["windir"] ~ `\system32\` ~ name ~ ".dll\0").ptr, GENERIC_READ,
					FILE_SHARE_READ | FILE_SHARE_WRITE, null,
					OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
				assert(hFile != INVALID_HANDLE_VALUE);
				scope(exit) enforce(CloseHandle(hFile));

				HANDLE hFileMap = enforce(CreateFileMappingA(hFile, null, PAGE_READONLY, 0, 0, null));
				scope(exit) enforce(CloseHandle(hFileMap));

				pExe = enforce(MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0));
			}
			scope(exit) enforce(UnmapViewOfFile(pExe));

			testPe(PEFile(pExe, false));
		}
		testPe(PEFile(enforce(GetModuleHandleA(name.ptr)), true));
	}

	test("ntdll", "sin", null);
	test("kernel32", "CreateFileW", ["ntdll.dll"]);
	test("user32", "GetCursor", ["GDI32.dll", "KERNEL32.dll", "ntdll.dll"]);

	auto kernel32 = PEFile(GetModuleHandleA("kernel32"), true);
	assert(GetCurrentThreadId() == (cast(typeof(GetCurrentThreadId)*)
		kernel32.exportedFunctions.find!`a.name == "GetCurrentThreadId"`()[0].address)());
	assert(GetCurrentThread() == (cast(typeof(GetCurrentThread)*)
		kernel32.exportedFunctions.find!`a.name == "GetCurrentThread"`()[0].address)());
}

version(unittest) {
	__gshared extern(C) extern:
	int _tls_index;
	void* _tlsstart, _tlsend, _tls_callbacks_a;
}
unittest {
	const pe = PEFile(GetModuleHandleA(null), true);
	const itd = pe.imageTlsDirectory;
	assert(itd);
	assert(itd.StartAddressOfRawData == cast(size_t) &_tlsstart);
	assert(itd.EndAddressOfRawData   == cast(size_t) &_tlsend);
	assert(itd.AddressOfIndex        == cast(size_t) &_tls_index);
	assert(itd.AddressOfCallBacks    == cast(size_t) &_tls_callbacks_a);
}

DWORD alignUp(DWORD x, DWORD y) pure nothrow { return ((x + (y - 1)) & (~(y - 1))); }
DWORD alignUown(DWORD x, DWORD y) pure nothrow { return (x & (~(y - 1))); }

extern (Windows) {
	alias ulong ULONGLONG;

	/*struct IMAGE_DOS_HEADER {      // DOS .EXE header
		WORD   e_magic;                     // Magic number
		WORD   e_cblp;                      // Bytes on last page of file
		WORD   e_cp;                        // Pages in file
		WORD   e_crlc;                      // Relocations
		WORD   e_cparhdr;                   // Size of header in paragraphs
		WORD   e_minalloc;                  // Minimum extra paragraphs needed
		WORD   e_maxalloc;                  // Maximum extra paragraphs needed
		WORD   e_ss;                        // Initial (relative) SS value
		WORD   e_sp;                        // Initial SP value
		WORD   e_csum;                      // Checksum
		WORD   e_ip;                        // Initial IP value
		WORD   e_cs;                        // Initial (relative) CS value
		WORD   e_lfarlc;                    // File address of relocation table
		WORD   e_ovno;                      // Overlay number
		WORD   e_res[4];                    // Reserved words
		WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
		WORD   e_oeminfo;                   // OEM information; e_oemid specific
		WORD   e_res2[10];                  // Reserved words
		LONG   e_lfanew;                    // File address of new exe header
	}*/

	struct IMAGE_FILE_HEADER {
		WORD    Machine;
		WORD    NumberOfSections;
		DWORD   TimeDateStamp;
		DWORD   PointerToSymbolTable;
		DWORD   NumberOfSymbols;
		WORD    SizeOfOptionalHeader;
		WORD    Characteristics;
	}

	/// Directory format.
	struct IMAGE_DATA_DIRECTORY {
		DWORD   VirtualAddress;
		DWORD   Size;
	}

	enum IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

	/// Optional header format.
	struct IMAGE_OPTIONAL_HEADER32 {
		//
		// Standard fields.
		//

		WORD    Magic;
		BYTE    MajorLinkerVersion;
		BYTE    MinorLinkerVersion;
		DWORD   SizeOfCode;
		DWORD   SizeOfInitializedData;
		DWORD   SizeOfUninitializedData;
		DWORD   AddressOfEntryPoint;
		DWORD   BaseOfCode;
		DWORD   BaseOfData;

		//
		// NT additional fields.
		//

		DWORD   ImageBase;
		DWORD   SectionAlignment;
		DWORD   FileAlignment;
		WORD    MajorOperatingSystemVersion;
		WORD    MinorOperatingSystemVersion;
		WORD    MajorImageVersion;
		WORD    MinorImageVersion;
		WORD    MajorSubsystemVersion;
		WORD    MinorSubsystemVersion;
		DWORD   Win32VersionValue;
		DWORD   SizeOfImage;
		DWORD   SizeOfHeaders;
		DWORD   CheckSum;
		WORD    Subsystem;
		WORD    DllCharacteristics;
		DWORD   SizeOfStackReserve;
		DWORD   SizeOfStackCommit;
		DWORD   SizeOfHeapReserve;
		DWORD   SizeOfHeapCommit;
		DWORD   LoaderFlags;
		DWORD   NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	}

	/// ditto
	struct IMAGE_OPTIONAL_HEADER64 {
		WORD        Magic;
		BYTE        MajorLinkerVersion;
		BYTE        MinorLinkerVersion;
		DWORD       SizeOfCode;
		DWORD       SizeOfInitializedData;
		DWORD       SizeOfUninitializedData;
		DWORD       AddressOfEntryPoint;
		DWORD       BaseOfCode;
		ULONGLONG   ImageBase;
		DWORD       SectionAlignment;
		DWORD       FileAlignment;
		WORD        MajorOperatingSystemVersion;
		WORD        MinorOperatingSystemVersion;
		WORD        MajorImageVersion;
		WORD        MinorImageVersion;
		WORD        MajorSubsystemVersion;
		WORD        MinorSubsystemVersion;
		DWORD       Win32VersionValue;
		DWORD       SizeOfImage;
		DWORD       SizeOfHeaders;
		DWORD       CheckSum;
		WORD        Subsystem;
		WORD        DllCharacteristics;
		ULONGLONG   SizeOfStackReserve;
		ULONGLONG   SizeOfStackCommit;
		ULONGLONG   SizeOfHeapReserve;
		ULONGLONG   SizeOfHeapCommit;
		DWORD       LoaderFlags;
		DWORD       NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	}


	struct IMAGE_NT_HEADERS64 {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	}

	struct IMAGE_NT_HEADERS32 {
		DWORD Signature;
		IMAGE_FILE_HEADER FileHeader;
		IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	}

	version(Win32) alias IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
	else IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;

	struct IMAGE_TLS_DIRECTORY64 {
		ULONGLONG   StartAddressOfRawData;
		ULONGLONG   EndAddressOfRawData;
		ULONGLONG   AddressOfIndex;         // PDWORD
		ULONGLONG   AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
		DWORD   SizeOfZeroFill;
		DWORD   Characteristics;
	}

	struct IMAGE_TLS_DIRECTORY32 {
		DWORD   StartAddressOfRawData;
		DWORD   EndAddressOfRawData;
		DWORD   AddressOfIndex;             // PDWORD
		DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
		DWORD   SizeOfZeroFill;
		DWORD   Characteristics;
	}

	version(Win32) alias IMAGE_TLS_DIRECTORY32 IMAGE_TLS_DIRECTORY;
	else IMAGE_TLS_DIRECTORY64 IMAGE_TLS_DIRECTORY;

	HMODULE LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
	HMODULE LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

	enum DONT_RESOLVE_DLL_REFERENCES = 1;
	enum LOAD_LIBRARY_AS_DATAFILE = 2;

	enum IMAGE_SIZEOF_SHORT_NAME = 8;

	struct IMAGE_SECTION_HEADER {
		char/*BYTE*/ Name[IMAGE_SIZEOF_SHORT_NAME];
		union MiscType {
				DWORD   PhysicalAddress;
				DWORD   VirtualSize;
		}
		MiscType Misc;
		DWORD   VirtualAddress;
		DWORD   SizeOfRawData;
		DWORD   PointerToRawData;
		DWORD   PointerToRelocations;
		DWORD   PointerToLinenumbers;
		WORD    NumberOfRelocations;
		WORD    NumberOfLinenumbers;
		DWORD   Characteristics;
	}

	struct IMAGE_IMPORT_DESCRIPTOR {
		union {
			DWORD   Characteristics;    // 0 for terminating null import descriptor
			DWORD   OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
		}
		DWORD   TimeDateStamp;              // 0 if not bound,
											// -1 if bound, and real date\time stamp
											//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
											// O.W. date/time stamp of DLL bound to (Old BIND)

		DWORD   ForwarderChain;                 // -1 if no forwarders
		DWORD   Name;
		DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
	}

	struct IMAGE_EXPORT_DIRECTORY {
		DWORD   Characteristics;
		DWORD   TimeDateStamp;
		WORD    MajorVersion;
		WORD    MinorVersion;
		DWORD   Name;
		DWORD   Base;
		DWORD   NumberOfFunctions;
		DWORD   NumberOfNames;
		DWORD   AddressOfFunctions;     // RVA from base of image
		DWORD   AddressOfNames;         // RVA from base of image
		DWORD   AddressOfNameOrdinals;  // RVA from base of image
	}
}
