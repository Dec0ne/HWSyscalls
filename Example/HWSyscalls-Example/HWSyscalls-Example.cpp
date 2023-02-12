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


int main(int argc, char* argv[]) {
	HANDLE targetHandle;
	OBJECT_ATTRIBUTES object;

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

	NTSTATUS status = pNtOpenProcess(&targetHandle, PROCESS_ALL_ACCESS, &object, &clientID);

	std::cout << "[+] NtOpenProcess result: " << status << std::endl;
	CloseHandle(targetHandle);

	if (DeinitHWSyscalls())
		std::cout << "[+] Cleaned up the exception handler." << std::endl;
	else
		std::cerr << "[-] Failed to clean up the exception handler." << std::endl;

	return 0;
}