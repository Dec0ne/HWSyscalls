#include <iostream>
#include "HWSyscalls.h"

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(WINAPI* NtOpenProcess_t)(
	OUT          PHANDLE            ProcessHandle,
	IN           ACCESS_MASK        DesiredAccess,
	IN           POBJECT_ATTRIBUTES ObjectAttributes,
	IN OPTIONAL  PCLIENT_ID         ClientId
	);

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);


int main(int argc, char* argv[]) {
	HANDLE targetHandle;
	OBJECT_ATTRIBUTES object;
	NTSTATUS status = 0;
	HANDLE sectionHandle = NULL;
	LARGE_INTEGER sectionSize = { 450 };

	if (!InitHWSyscalls())
		return -1;

	object.Length = sizeof(OBJECT_ATTRIBUTES);
	object.ObjectName = NULL;
	object.Attributes = NULL;
	object.RootDirectory = NULL;
	object.SecurityDescriptor = NULL;
	int pid = atoi(argv[1]);
	
	CLIENT_ID clientID = { (HANDLE)pid, NULL };

	NtOpenProcess_t pNtOpenProcess = (NtOpenProcess_t)PrepareSyscall((char*)"NtOpenProcess");
	if (!pNtOpenProcess) {
		std::cerr << "[-] Failed to prepare syscall for NtOpenProcess." << std::endl;
		return -2;
	}
	status = pNtOpenProcess(&targetHandle, PROCESS_ALL_ACCESS, &object, &clientID);
	std::cout << "[+] NtOpenProcess result: " << status << std::endl;

	// Added example for NtCreateSection to test the stack arguments as well (arguments #4+)
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t)PrepareSyscall((char*)"NtCreateSection");
	if (!pNtOpenProcess) {
		std::cerr << "[-] Failed to prepare syscall for NtCreateSection." << std::endl;
		return -2;
	}
	status = pNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	std::cout << "[+] NtCreateSection result: " << status << std::endl;

	CloseHandle(targetHandle);

	if (DeinitHWSyscalls())
		std::cout << "[+] Cleaned up the exception handler." << std::endl;
	else
		std::cerr << "[-] Failed to clean up the exception handler." << std::endl;
	
	getchar();

	return 0;
}