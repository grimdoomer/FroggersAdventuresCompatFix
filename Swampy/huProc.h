/*

*/

#pragma once
#include <Windows.h>
#include <setjmp.h>

extern void(__cdecl *PrintDbgString)(const char *psFormat, ...);

typedef void(__cdecl  *huTask_WorkProc)();

// sizeof = 0x68
struct huTask
{
	/* 0x00 */ _JUMP_BUFFER RegisterState;
	/* 0x40 */ huTask	*pBLink;
	/* 0x44 */ huTask	*pFLink;
	/* 0x48 */ WORD Flags;
	/* 0x4A */ WORD Unk3;
	/* 0x4C */ WORD Unk1;
	/* 0x4E */ WORD ProcessId;
	/* 0x50 */ WORD ParentProcessId;
	/* 0x52 */ WORD Unk2;
	/* 0x54 */ int TaskStatus;	// Gets set to 0xFFFFFFFF on task exit
	/* 0x58 */ huTask_WorkProc pFunction;
	/* 0x5C */ void *pUnkFunc;		// another function pointer
	/* 0x60 */ DWORD StackSize;
	/* 0x64 */ void *StackAllocation;
};
static_assert(sizeof(huTask) == 0x68, "huTask incorrect struct size");

struct huTaskThreadInfo
{
	HANDLE hThread;				// Worker thread handle
	DWORD ThreadId;				// Worker thread id
	HANDLE hWorkerRunEvent;		// Signaled when the worker should wake and do work
	HANDLE hWorkerSleepEvent;	// Signaled when the worker has gone to sleep and a new task should be scheduled
};

void huProc_InstallHooks();