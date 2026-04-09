#include <windows.h>
#include <iostream>
#include <iomanip>

using namespace std;

BOOL isValidDosHeader(PCHAR buff);
BOOL isValidNtHeader(PCHAR buff);
PCHAR getFile(char* argv[]);
DWORD getSizeOfImage(PCHAR buff); 
PCHAR allocVirtualMem(PCHAR tmpBuff);

int main(int argc, char* argv[]) {
    if (argc != 2){
        cout << "Wrong number of arguments! Command form: .\\pe_loader.exe <FilePath>" << endl;
        exit(1);
    }

    PCHAR tmpBuff = getFile(argv);

    if (!isValidDosHeader(tmpBuff) || !isValidNtHeader(tmpBuff)){
        HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
        exit(1);
    }

    PCHAR pImageBase = allocVirtualMem(tmpBuff);

    // TODO: Section Mapping

    VirtualFree(pImageBase, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
    
    return 0;
}

/**
 * @brief Allocates the final virtual memory space required for the PE image to execute.
 * It parses the Optional Header to find the SizeOfImage and requests executable memory from the OS.
 * @param tmpBuff Pointer to the raw PE file data (used to extract SizeOfImage).
 * @return PCHAR A pointer to the newly allocated executable memory (ImageBase). 
 * The caller must free this using VirtualFree. Exits the program if allocation fails.
 */
PCHAR allocVirtualMem(PCHAR tmpBuff){
    DWORD sizeOfImage = getSizeOfImage(tmpBuff);
    
    PCHAR pImageBase = (PCHAR)VirtualAlloc(
        NULL,
        sizeOfImage,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
        
    if (pImageBase == NULL) {
        cout << "[-] VirtualAlloc failed!" << endl;
        HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
        exit(1);
    }
    
    cout << "[+] Allocated virtual memory for the image at: 0x" << hex << (uintptr_t)pImageBase << endl;

    return pImageBase;
}

/**
 * @brief Reads the raw contents of a file from the disk into a dynamically allocated heap buffer.
 * @param argv Array containing the file path at index 1.
 * @return PCHAR A pointer to the heap-allocated buffer containing the raw file data.
 * The caller is responsible for freeing this memory using HeapFree.
 */
PCHAR getFile(char* argv[]){
    LPCSTR pFilePath = argv[1];
    HANDLE hFile = CreateFileA(
        pFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
        
    if (hFile == INVALID_HANDLE_VALUE){
        cout << "[-] Failed to open file!" << endl;
        exit(1);
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    
    PCHAR tmpBuff = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
    if (tmpBuff == NULL){
        cout << "[-] HeapAlloc failed!" << endl;
        CloseHandle(hFile);
        exit(1);
    }

    DWORD bytesRead = 0;
    ReadFile(hFile, tmpBuff, fileSize, &bytesRead, NULL);
    if (bytesRead != fileSize){
        cout << "[-] ReadFile failed!" << endl;
        CloseHandle(hFile);
        HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
        exit(1);
    }
    CloseHandle(hFile);

    return tmpBuff;
}

/**
 * @brief Validates the presence of the DOS header signature (MZ) in the given buffer.
 * @param buff Pointer to the raw PE file data.
 * @return BOOL True if the signature is "MZ" (0x5A4D), False otherwise.
 */
BOOL isValidDosHeader(PCHAR buff){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE){
        cout << "[+] Valid DOS header (MZ)" << endl;
        return true;
    } 
    else{
        cout << "[-] Invalid file format!" << endl;
        return false;
    }
}

/**
 * @brief Validates the presence of the NT header signature (PE\0\0) in the given buffer.
 * @param buff Pointer to the raw PE file data.
 * @return BOOL True if the signature is "PE\0\0" (0x00004550), False otherwise.
 */
BOOL isValidNtHeader(PCHAR buff){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(buff + e_lfanew);
    
    if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE){
        cout << "[+] Valid NT header (PE\\0\\0)" << endl;
        return true;
    }
    else{
        cout << "[-] Invalid NT header (signature)" << endl;
        return false;
    }
}

/**
 * @brief Retrieves the total virtual memory size required to load the PE image.
 * @param buff Pointer to the raw PE file data.
 * @return DWORD The size of the image in bytes (SizeOfImage from the Optional Header).
 */
DWORD getSizeOfImage(PCHAR buff){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(buff + e_lfanew);

    return pNtHeaders->OptionalHeader.SizeOfImage;
}