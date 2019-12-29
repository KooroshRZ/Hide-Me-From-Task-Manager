#pragma once

#define _CRT_SECURE_WARNINGS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>

void StartHook();

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {

	ULONG				NextEntryOffset;
	ULONG				NumberOfThreads;
	LARGE_INTEGER		Reserved[3];
	LARGE_INTEGER		CreateTime;
	LARGE_INTEGER		UserTime;
	LARGE_INTEGER		KernelTime;
	UNICODE_STRING		ImageName;
	ULONG				BasePriority;
	HANDLE				ProcessId;
	HANDLE				InheritedFromProcessId;

} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION) (

	__in		SYSTEM_INFORMATION_CLASS	SystemInformaionClass,
	__inout		PVOID						SystemInformation,
	__in		ULONG						SystemInformationLength,
	__out_opt	PULONG						ReturnLength

);

NTSTATUS WINAPI HookedNtQuerySystemInformation(

	__in		SYSTEM_INFORMATION_CLASS	SystemInformationClass,
	__inout		PVOID						SystemInformation,
	__in		ULONG						SystemInformationLength,
	__out_opt	PULONG						ReturnLength

);