
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

	printf("Offset to PE Header: 0x%x = %d\n\n", DOSHeader->e_lfanew, DOSHeader->e_lfanew);

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)lpHeaderAddr + DOSHeader->e_lfanew);

	//add the offset in bytes to get to NT Headers 
	return (PIMAGE_NT_HEADERS)((PBYTE)lpHeaderAddr + DOSHeader->e_lfanew);
}


//typedef struct _IMAGE_NT_HEADERS64 {
//	DWORD Signature;
//	IMAGE_FILE_HEADER FileHeader;
//	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
//} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

//typedef struct _IMAGE_FILE_HEADER {
//	WORD    Machine;
//	WORD    NumberOfSections;
//	DWORD   TimeDateStamp;
//	DWORD   PointerToSymbolTable;
//	DWORD   NumberOfSymbols;
//	WORD    SizeOfOptionalHeader;
//	WORD    Characteristics;
//} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

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
//    DWORD   SizeOfCode;
//    DWORD   SizeOfInitializedData;
//    DWORD   SizeOfUninitializedData;
//    DWORD   AddressOfEntryPoint;
//    DWORD   BaseOfCode;
//    DWORD   BaseOfData;
//
//    //
//    // NT additional fields.
//    //
//
//    DWORD   ImageBase;
//    DWORD   SectionAlignment;
//    DWORD   FileAlignment;
//    WORD    MajorOperatingSystemVersion;
//    WORD    MinorOperatingSystemVersion;
//    WORD    MajorImageVersion;
//    WORD    MinorImageVersion;
//    WORD    MajorSubsystemVersion;
//    WORD    MinorSubsystemVersion;
//    DWORD   Win32VersionValue;
//    DWORD   SizeOfImage;
//    DWORD   SizeOfHeaders;
//    DWORD   CheckSum;
//    WORD    Subsystem;
//    WORD    DllCharacteristics;
//    DWORD   SizeOfStackReserve;
//    DWORD   SizeOfStackCommit;
//    DWORD   SizeOfHeapReserve;
//    DWORD   SizeOfHeapCommit;
//    DWORD   LoaderFlags;
//    DWORD   NumberOfRvaAndSizes;
//    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;


int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("Usage: PE_Parser.exe <file>");
		return 1;
	}
	
	LPVOID lpPEBuff = ReadPE("C:\\Users\\User\\source\\repos\\PE_Parser\\x64\\Release\\PE_Parser.exe");

	PIMAGE_NT_HEADERS pNTHeaders = ParseDOSHeader(lpPEBuff);
	
	IMAGE_FILE_HEADER FileHdr = pNTHeaders->FileHeader;

	printf("### PARSING FILE HEADER ###\n\n");
	
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


	return 0;
}

