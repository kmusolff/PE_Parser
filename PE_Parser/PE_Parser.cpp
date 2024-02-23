
#include <windows.h>
#include <cstdio>

LPVOID ReadPE(LPCSTR lpFileName) {
	
	HANDLE hFile = CreateFileA(lpFileName, GENERIC_READ, 0, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL);

	DWORD dwFileSize = 0;

	GetFileSize(hFile, &dwFileSize);

	LPVOID lpPEBuffer = HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, dwFileSize);

	if (!ReadFile(hFile, lpPEBuffer, dwFileSize, NULL, NULL)) {
		printf("Error reading file: %d", GetLastError());
	}

	return lpPEBuffer;
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("Usage: PE_Parser.exe <file>");
		return 1;
	}
	
	LPVOID lpPEBuff = ReadPE(argv[1]);

	

	return 0;
}

