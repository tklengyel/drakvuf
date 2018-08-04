#pragma once

#include <Windows.h>
//#include <SubAuth.h>

/*
 * cf. https://github.com/hasherezade/process_doppelganging/blob/master/ntdll_types
 *
 * We can also get structure definitions with WinDng :
	dt nt!_STRUCTURE_TYPE
 */
#define PS_INHERIT_HANDLES 4
/*
 * https://processhacker.sourceforge.io/doc/ntrtl_8h.html
 */
#define RTL_USER_PROC_PARAMS_NORMALIZED 1

/*
 * Source : https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wudfwdm/ns-wudfwdm-_object_attributes
 *
 * We need to declare this structure because it is not in the standard header,
 * we could probably do another way by copying the kernel headers into the project.
 */
/*
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
*/

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG  TimeStamp;
    STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _MY_RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                            // Should be set before call RtlCreateProcessParameters
    ULONG Length;                                   // Length of valid structure
    ULONG Flags;                                    // Currently only PPF_NORMALIZED (1) is known:
    //  - Means that structure is normalized by call RtlNormalizeProcessParameters
    ULONG DebugFlags;
    PVOID ConsoleHandle;                            // HWND to console window associated with process (if any).
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;                        // Specified in DOS-like symbolic link path, ex: "C:/WinNT/SYSTEM32"
    UNICODE_STRING DllPath;                         // DOS-like paths separated by ';' where system should search for DLL files.
    UNICODE_STRING ImagePathName;                   // Full path in DOS-like format to process'es file image.
    UNICODE_STRING CommandLine;                     // Command line
    PVOID Environment;                              // Pointer to environment block (see RtlCreateEnvironment)
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;                            // Fill attribute for console window
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;                     // Name of WindowStation and Desktop objects, where process is assigned
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[0x20];
    ULONGLONG EnvironmentSize;
    ULONGLONG EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
} MY_RTL_USER_PROCESS_PARAMETERS, *MY_PRTL_USER_PROCESS_PARAMETERS;

/*
 * Slightly modified version of : https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx
 *
 * Modified with info from windbg (dt nt!_PEB). Only the fields relevant to
 * the specific task of this program are listed here.
 *
 * Size = 1964
 */
typedef struct _MY_PEB
{
    BYTE							Reserved1[2];
    BYTE							BeingDebugged;
    BYTE							Reserved2[13];
    PVOID							ImageBaseAddress;
    PPEB_LDR_DATA					Ldr;
    PRTL_USER_PROCESS_PARAMETERS	ProcessParameters;
    BYTE							Reserved3[520];
    PVOID							PostProcessInitRoutine;
    BYTE							Reserved4[136];
    ULONG							SessionId;
} MY_PEB, *MY_PPEB;

/*
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,			// Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	MaxProcessInfoClass				// MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;
*/

/*
 * https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms684280(v=vs.85).aspx
 */
/*
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
*/

/*
 * Pointer to the NtCreateSection() function.
 */
typedef NTSTATUS (NTAPI* NT_CREATE_SECTION)(
    PHANDLE				SectionHandle,
    ACCESS_MASK			DesiredAccess,
    POBJECT_ATTRIBUTES	ObjectAttributes,
    PLARGE_INTEGER		MaximumSize,
    ULONG				SectionPageProtection,
    ULONG				AllocationAttributes,
    HANDLE				FileHandle
);

/*
 * Pointer to the NtCreatProcessEx() function.
 */
typedef NTSTATUS (NTAPI* NT_CREATE_PROCESS_EX)
(
    OUT PHANDLE				ProcessHandle,
    IN ACCESS_MASK			DesiredAccess,
    IN POBJECT_ATTRIBUTES	ObjectAttributes	OPTIONAL,
    IN HANDLE				ParentProcess,
    IN ULONG				Flags,
    IN HANDLE				SectionHandle		OPTIONAL,
    IN HANDLE				DebugPort			OPTIONAL,
    IN HANDLE				ExceptionPort		OPTIONAL,
    IN BOOLEAN				InJob
);

/*
 * Pointer to the NtCreatThreadEx() function.
 */
typedef NTSTATUS (NTAPI* NT_CREATE_THREAD_EX) (
    OUT PHANDLE					ThreadHandle,
    IN  ACCESS_MASK				DesiredAccess,
    IN  POBJECT_ATTRIBUTES		ObjectAttributes	OPTIONAL,
    IN  HANDLE					ProcessHandle,
    IN  LPTHREAD_START_ROUTINE	StartRoutine,
    IN  PVOID					Argument			OPTIONAL,
    IN  ULONG					CreateFlags,
    IN  ULONG_PTR				ZeroBits,
    IN  SIZE_T					StackSize			OPTIONAL,
    IN  SIZE_T					MaximumStackSize	OPTIONAL,
    IN  PVOID					AttributeList		OPTIONAL
);

typedef DWORD(WINAPI* RTL_CREATE_USER_THREAD) (
    IN HANDLE 					ProcessHandle,
    IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
    IN BOOL 					CreateSuspended,
    IN ULONG					StackZeroBits,
    IN OUT PULONG				StackReserved,
    IN OUT PULONG				StackCommit,
    IN LPVOID					StartAddress,
    IN LPVOID					StartParameter,
    OUT HANDLE 					ThreadHandle,
    OUT LPVOID					ClientID
);

/*
 * Pointer to the RtlCreateProcessParameters() function.
 */
typedef NTSTATUS(NTAPI* RTL_CREATE_PROCESS_PARAMETERS_EX)(
    OUT PRTL_USER_PROCESS_PARAMETERS*	pProcessParameters,
    IN	PUNICODE_STRING					ImagePathName,
    IN	PUNICODE_STRING					DllPath				OPTIONAL,
    IN	PUNICODE_STRING					CurrentDirectory	OPTIONAL,
    IN	PUNICODE_STRING					CommandLine			OPTIONAL,
    IN	PVOID							Environment			OPTIONAL,
    IN	PUNICODE_STRING					WindowTitle			OPTIONAL,
    IN	PUNICODE_STRING					DesktopInfo			OPTIONAL,
    IN	PUNICODE_STRING					ShellInfo			OPTIONAL,
    IN	PUNICODE_STRING					RuntimeData			OPTIONAL,
    IN	ULONG							Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
);

/*
 * Pointer to the RtlInitUnicodeString() function.
 */
typedef VOID (NTAPI* RTL_INIT_UNICODE_STRING)(
    OUT	PUNICODE_STRING DestinationString,
    IN	PCWSTR          SourceString	OPTIONAL
);

/*
 * Pointer to the NtQueryInformationProcess() function.
 */
typedef NTSTATUS (NTAPI* NT_QUERY_INFORMATION_PROCESS)(
    IN	HANDLE				ProcessHandle,
    IN	PROCESSINFOCLASS	ProcessInformationClass,
    IN	PVOID				ProcessInformation,
    IN	ULONG				ProcessInformationLength,
    OUT	PULONG				ReturnLength	OPTIONAL
);

/*
 * Pointer to the NtReadVirtualMemory() function.
 */
typedef NTSTATUS (NTAPI* NT_READ_VIRTUAL_MEMORY)(
    IN	HANDLE	ProcessHandle,
    IN	PVOID	BaseAddress,
    OUT	PVOID	Buffer				OPTIONAL,
    IN	SIZE_T	BufferSize,
    OUT	PSIZE_T	NumberOfBytesRead	OPTIONAL
);

/*
 * Pointer to the NtWriteVirtualMemory() function.
 */
typedef NTSTATUS(NTAPI* NT_WRITE_VIRTUAL_MEMORY)(
    IN	HANDLE	ProcessHandle,
    IN	PVOID	BaseAddress,
    OUT	PVOID	Buffer				OPTIONAL,
    IN	SIZE_T	BufferSize,
    OUT	PSIZE_T	NumberOfBytesRead	OPTIONAL
);
/*
 * Pointer to the RtlCreateEnvironment() function.
 */
typedef NTSTATUS (NTAPI* RTL_CREATE_ENVIRONMENT)(
    IN	BOOLEAN Inherit,
    OUT	PVOID*	Environment
);
