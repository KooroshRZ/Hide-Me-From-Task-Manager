#pragma once

#define _CRT_SECURE_WARNINGS

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <winternl.h>
#include <Psapi.h>

void StartHook();