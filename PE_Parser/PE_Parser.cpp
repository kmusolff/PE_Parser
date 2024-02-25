
#include <windows.h>
#include <cstdio>


LPVOID ReadPE(LPCSTR lpFileName) {
	printf("Opening File %s\n\n", lpFileName);
	HANDLE hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Error opening file: %d\n", GetLastError());
		exit(1);
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	LPVOID lpPEBuffer = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, dwFileSize);

	if (!ReadFile(hFile, lpPEBuffer, dwFileSize, NULL, NULL)) {
		printf("Error reading file: %d\n", GetLastError());
		exit(1);
	}

	return lpPEBuffer;
}

//typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
//	WORD   e_magic;                     // Magic number
//	WORD   e_cblp;                      // Bytes on last page of file
//	WORD   e_cp;                        // Pages in file
//	WORD   e_crlc;                      // Relocations
//	WORD   e_cparhdr;                   // Size of header in paragraphs
//	WORD   e_minalloc;                  // Minimum extra paragraphs needed
//	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
//	WORD   e_ss;                        // Initial (relative) SS value
//	WORD   e_sp;                        // Initial SP value
//	WORD   e_csum;                      // Checksum
//	WORD   e_ip;                        // Initial IP value
//	WORD   e_cs;                        // Initial (relative) CS value
//	WORD   e_lfarlc;                    // File address of relocation table
//	WORD   e_ovno;                      // Overlay number
//	WORD   e_res[4];                    // Reserved words
//	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
//	WORD   e_oeminfo;                   // OEM information; e_oemid specific
//	WORD   e_res2[10];                  // Reserved words
//	LONG   e_lfanew;                    // File address of new exe header
//} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

PIMAGE_NT_HEADERS ParseDOSHeader(LPVOID lpHeaderAddr) {

	printf("### PARSING DOS HEADER ###\n\n");
	PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)(lpHeaderAddr);

	// To extract ASCII Values, we can cast WORD to char and shift 
	printf("DOS Header Magic: 0x%x %c%c\n", DOSHeader->e_magic, (char)(DOSHeader->e_magic), (char)(DOSHeader->e_magic >> 8));

	printf("Offset to NT Headers: 0x%x = %d\n\n", DOSHeader->e_lfanew, DOSHeader->e_lfanew);

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)lpHeaderAddr + DOSHeader->e_lfanew);

	//add the offset in bytes to get to NT Headers, hence casting to PBYTE
	return (PIMAGE_NT_HEADERS)((PBYTE)lpHeaderAddr + DOSHeader->e_lfanew);
}


//typedef struct _IMAGE_NT_HEADERS64 {
//	DWORD Signature;
//	IMAGE_FILE_HEADER FileHeader;
//	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
//} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;


//typedef struct _IMAGE_OPTIONAL_HEADER64 {
//	WORD        Magic;
//	BYTE        MajorLinkerVersion;
//	BYTE        MinorLinkerVersion;
//	DWORD       SizeOfCode;
//	DWORD       SizeOfInitializedData;
//	DWORD       SizeOfUninitializedData;
//	DWORD       AddressOfEntryPoint;
//	DWORD       BaseOfCode;
//	ULONGLONG   ImageBase;
//	DWORD       SectionAlignment;
//	DWORD       FileAlignment;
//	WORD        MajorOperatingSystemVersion;
//	WORD        MinorOperatingSystemVersion;
//	WORD        MajorImageVersion;
//	WORD        MinorImageVersion;
//	WORD        MajorSubsystemVersion;
//	WORD        MinorSubsystemVersion;
//	DWORD       Win32VersionValue;
//	DWORD       SizeOfImage;
//	DWORD       SizeOfHeaders;
//	DWORD       CheckSum;
//	WORD        Subsystem;
//	WORD        DllCharacteristics;
//	ULONGLONG   SizeOfStackReserve;
//	ULONGLONG   SizeOfStackCommit;
//	ULONGLONG   SizeOfHeapReserve;
//	ULONGLONG   SizeOfHeapCommit;
//	DWORD       LoaderFlags;
//	DWORD       NumberOfRvaAndSizes;
//	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

//typedef struct _IMAGE_OPTIONAL_HEADER {
//    //
//    // Standard fields.
//    //
//
//    WORD    Magic;
//    BYTE    MajorLinkerVersion;
//    BYTE    MinorLinkerVersion;
//    DWORD   SizeOfCode; // Size of .code section in bytes
//    DWORD   SizeOfInitializedData; // Size of .data section in bytes
//    DWORD   SizeOfUninitializedData;	// Size of .bss section in bytes, represents memory allocated for uninitialized global and static variables, 
										// it reserves space for these variables in memory, which are initialized to zero during program startup.
//    DWORD   AddressOfEntryPoint; // EntryPoint RVA, located in .text section
//    DWORD   BaseOfCode; // the RVA of the .code section 
//    DWORD   BaseOfData; // the RVA of the .data section 
//    //
//    // NT additional fields.
//    //
//    DWORD   ImageBase; // preferred base address of image in memory
//    DWORD   SectionAlignment;
//    DWORD   FileAlignment;
//    WORD    MajorOperatingSystemVersion;
//    WORD    MinorOperatingSystemVersion;
//    WORD    MajorImageVersion;
//    WORD    MinorImageVersion;
//    WORD    MajorSubsystemVersion;
//    WORD    MinorSubsystemVersion;
//    DWORD   Win32VersionValue;
//    DWORD   SizeOfImage;		//size of the image in memory when the executable file is loaded into the process's address space
//    DWORD   SizeOfHeaders;	//size of all headers preceding the first section
//    DWORD   CheckSum;
//    WORD    Subsystem;
//    WORD    DllCharacteristics;
//    DWORD   SizeOfStackReserve;
//    DWORD   SizeOfStackCommit;
//    DWORD   SizeOfHeapReserve;
//    DWORD   SizeOfHeapCommit;
//    DWORD   LoaderFlags;
//    DWORD   NumberOfRvaAndSizes;	// number of entries in the data directory, 0x10 = 16 by default
//    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;




//typedef struct _IMAGE_DATA_DIRECTORY {
//	DWORD   VirtualAddress;
//	DWORD   Size;
//} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

//typedef struct _IMAGE_FILE_HEADER {
//	WORD    Machine;
//	WORD    NumberOfSections;
//	DWORD   TimeDateStamp;
//	DWORD   PointerToSymbolTable;
//	DWORD   NumberOfSymbols;
//	WORD    SizeOfOptionalHeader;
//	WORD    Characteristics;
//} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;
void ParseFileHeader(IMAGE_FILE_HEADER FileHdr) {
	WORD arch = FileHdr.Machine;

	if (arch == IMAGE_FILE_MACHINE_AMD64) {
		printf("Machine: %d -> x64\n", arch);

	}
	else if (arch == IMAGE_FILE_MACHINE_I386) {
		printf("Machine: %d -> x86\n", arch);
	}
	else {
		printf("Machine: %d -> ARM?\n", arch);
	}

	WORD wChar = FileHdr.Characteristics;

	if (wChar & IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("Characteristics: Executable\n");
	}
	if (wChar & IMAGE_FILE_DLL) {
		printf("Characteristics: DLL\n");
	}

	printf("Number of sections: %d\n", FileHdr.NumberOfSections);
}

void ParseOptHeader(IMAGE_OPTIONAL_HEADER OptHdr) {

	printf("Magic: 0x%x\n", OptHdr.Magic);

	printf("Size of .code: 0x%x = %d\n", OptHdr.SizeOfCode, OptHdr.SizeOfCode);

	printf("Size of image in memory: 0x%x = %d\n", OptHdr.SizeOfImage, OptHdr.SizeOfImage);

	printf("Size of headers (RVA of first section): 0x%x = %d\n", OptHdr.SizeOfHeaders, OptHdr.SizeOfHeaders);
	
}

const char* directory_entries[] = {
	"IMAGE_DIRECTORY_ENTRY_EXPORT",    // Export Directory
	"IMAGE_DIRECTORY_ENTRY_IMPORT",    // Import Directory
	"IMAGE_DIRECTORY_ENTRY_RESOURCE",  // Resource Directory
	"IMAGE_DIRECTORY_ENTRY_EXCEPTION", // Exception Directory
	"IMAGE_DIRECTORY_ENTRY_SECURITY",  // Security Directory
	"IMAGE_DIRECTORY_ENTRY_BASERELOC", // Base Relocation Table
	"IMAGE_DIRECTORY_ENTRY_DEBUG",     // Debug Directory
	"IMAGE_DIRECTORY_ENTRY_COPYRIGHT", // (X86 usage)
	"IMAGE_DIRECTORY_ENTRY_ARCHITECTURE",    // Architecture Specific Data
	"IMAGE_DIRECTORY_ENTRY_GLOBALPTR",       // RVA of GP
	"IMAGE_DIRECTORY_ENTRY_TLS",             // TLS Directory
	"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",     // Load Configuration Directory
	"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",    // Bound Import Directory in headers
	"IMAGE_DIRECTORY_ENTRY_IAT",             // Import Address Table
	"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",    // Delay Load Import Descriptors
	"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"  // COM Runtime descriptor
};


void ParseDataDir(IMAGE_OPTIONAL_HEADER OptHdr, LPDWORD ImpDir, LPDWORD ExpDir, LPDWORD BaseReloc) {
	for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
		printf("Data directory index %d (%s): RVA=%d Size=%d\n", i,directory_entries[i], OptHdr.DataDirectory[i].VirtualAddress, OptHdr.DataDirectory[i].Size);
	}

	*ImpDir = OptHdr.DataDirectory[1].VirtualAddress;
	*ExpDir = OptHdr.DataDirectory[0].VirtualAddress;
	*BaseReloc = OptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

	printf("%d %d %d\n", *ImpDir, *ExpDir, *BaseReloc);
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("Usage: PE_Parser.exe <file>");
		return 1;
	}
	
	LPVOID lpPEBuff = ReadPE(argv[1]);

	PIMAGE_NT_HEADERS pNTHeaders = ParseDOSHeader(lpPEBuff);
	
	

	printf("### PARSING NT HEADERS ###\n\n");

	DWORD dSignature = pNTHeaders->Signature;

	printf("Signature: 0x%x, %c%c\n\n", dSignature, (char)(dSignature), (char)(dSignature >> 8));

	printf("### PARSING FILE HEADER ###\n\n");

	IMAGE_FILE_HEADER FileHdr = pNTHeaders->FileHeader;
	
	ParseFileHeader(FileHdr);
	

	printf("\n### PARSING OPTIONAL HEADER ###\n\n");

	IMAGE_OPTIONAL_HEADER OptHdr = (IMAGE_OPTIONAL_HEADER)pNTHeaders->OptionalHeader;

	ParseOptHeader(OptHdr);

	printf("\n### PARSING DATA DIRECTORY ###\n\n");

	DWORD lpExpOffset = 0;
	DWORD lpImpOffset = 0;

	DWORD lpBaseRelocOffset = 0;

	ParseDataDir(OptHdr, &lpImpOffset, &lpExpOffset, &lpBaseRelocOffset);

	return 0;
}

