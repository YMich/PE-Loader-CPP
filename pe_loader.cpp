#include <windows.h>
#include <iostream>
#include <iomanip>

#define IMAGE_REL_BASED_DIR64 10

using namespace std;

BOOL isValidDosHeader(PCHAR buff);
BOOL isValidNtHeader(PCHAR buff);
PCHAR getFile(char* argv[]);
DWORD getSizeOfImage(PCHAR buff); 
PCHAR allocVirtualMem(PCHAR tmpBuff);
void copyHeaders(PCHAR peBuff, PCHAR pImageBase);
void copySections(PCHAR peBuff, PCHAR pImageBase);
void fixAbsoluteAddresses(PCHAR peBuff, PCHAR pImageBase);

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

    copyHeaders(tmpBuff, pImageBase);
    copySections(tmpBuff, pImageBase);
    
    HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
    cout << "[+] Freed temporary raw file buffer." << endl;

    fixAbsoluteAddresses(pImageBase);

    VirtualFree(pImageBase, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, (LPVOID)tmpBuff);
    
    return 0;
}

/**
 * @brief Applies Base Relocations to the mapped image if it was loaded at a different ImageBase.
 * @param pImageBase Pointer to the allocated and mapped virtual memory.
 */
void fixAbsoluteAddresses(PCHAR pImageBase){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pImageBase + pDosHeader->e_lfanew);

    DWORD sizeRelocationDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    DWORD rvaRelocationDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    if (sizeRelocationDir == 0) {
        cout << "[*] No relocations found or needed." << endl;
        return;
    }

    ULONG_PTR delta = (ULONG_PTR)pImageBase - pNtHeaders->OptionalHeader.ImageBase;

    if (delta == 0) {
        cout << "[+] Image loaded at preferred base address. No relocations required." << endl;
        return;
    }

    DWORD currRealocBlock = 0;
    while (currRealocBlock < sizeRelocationDir){

        PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(pImageBase + rvaRelocationDir + currRealocBlock);
        DWORD countEntry = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD entries = (PWORD)(relocBlock + 1);

        for (DWORD i = 0; i < countEntry; i++){
            BYTE type = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64){
                PDWORD64 pAddressToFix = (PDWORD64)(pImageBase + relocBlock->VirtualAddress + offset);
                
                *pAddressToFix += delta;
            }
        }

        currRealocBlock += relocBlock->SizeOfBlock;
    }
    
    cout << "[+] Fixed absolute addresses successfully (Applied " << sizeRelocationDir << " bytes of relocations)" << endl;
}

/**
 * @brief Copies the PE headers (DOS, NT, and Section Table) to the allocated virtual memory.
 * @param peBuff Pointer to the raw PE file data.
 * @param pImageBase Pointer to the allocated virtual memory.
 */
void copyHeaders(PCHAR peBuff, PCHAR pImageBase){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peBuff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(peBuff + e_lfanew);

    DWORD sizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
    memcpy(pImageBase, peBuff, sizeOfHeaders);

    cout << "[+] Copied headers (" << sizeOfHeaders << " bytes) to virtual memory" << endl;
}

/**
 * @brief Maps each section from the raw file buffer to its correct VirtualAddress in memory.
 * @param peBuff Pointer to the raw PE file data.
 * @param pImageBase Pointer to the allocated virtual memory.
 */
void copySections(PCHAR peBuff, PCHAR pImageBase){
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)peBuff;
    LONG e_lfanew = pDosHeader->e_lfanew;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(peBuff + e_lfanew);

    WORD numberOfSections = pNtHeaders->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    
    for (int i = 0; i < numberOfSections; i++){
        CHAR sSectionName[9] = {0};
        memcpy(sSectionName, pSectionHeader[i].Name, 8);

        if (pSectionHeader[i].SizeOfRawData > 0) {
            memcpy(pImageBase + pSectionHeader[i].VirtualAddress, 
                   peBuff + pSectionHeader[i].PointerToRawData, 
                   pSectionHeader[i].SizeOfRawData);

            cout << "[+] Section: " << left << setw(8) << sSectionName 
                 << " copied to virtual address: 0x" 
                 << right << hex << setfill('0') << setw(8) << (uintptr_t)(pImageBase + pSectionHeader[i].VirtualAddress) << endl;
        } else {
            cout << "[*] Section: " << left << setw(8) << sSectionName 
                 << " has no raw data (skipped copying)" << endl;
        }
    }
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