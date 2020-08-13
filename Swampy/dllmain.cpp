// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <detours.h>
#include "huProc.h"

void **huMemAllocPtr = (void**)0x212E968;

void * (__cdecl *huMemAllocHelper)(DWORD size) = (void*(__cdecl*)(DWORD))0x415141;

void * uiInitProcHookAddress = (void*)0x4128A1;

void * uiInitDispatchWorkerAddress = (void*)0x4127E0;
void * uiInitDoWorkAddress = (void*)0x412847;

void(__cdecl *MusicTick)() = (void(__cdecl*)())0x41DBD7;
DWORD g_SoundState = 0;

void(__cdecl *MainMenuUpdate)(WORD procId) = (void(__cdecl*)(WORD))0x4DA72E;

// Require for detours.
void __declspec(dllexport) DummyExport()
{

}

void * __cdecl Hook_huMemAllocHelper(DWORD size)
{
	// Allocate memory from heap instead of stack.
	void *pAllocation = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);

	// Check if the allocation pointer has been setup yet.
	if (*huMemAllocPtr == nullptr)
	{
		// Set the allocation pointer.
		*huMemAllocPtr = pAllocation;
	}

	// Return the allocation pointer.
	return pAllocation;
}

void __declspec(naked) Hook_uiInitProc()
{
	_asm
	{
		// Bail out instead of spinning for task completion.
		mov		esp, ebp
		pop		ebp
		ret
	}
}

void __cdecl Hook_MusicTick()
{
	// If the sound state counter has reached the correct state update music.
	if (g_SoundState >= 2)
	{
		// Call the trampoline.
		MusicTick();
	}
}

void __cdecl Hook_MainMenuUpdate(WORD procId)
{
	// Check if we need to update the sound state.
	if (g_SoundState < 2)
		g_SoundState++;

	// Call the trampoline.
	MainMenuUpdate(procId);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		// Restore the imports table.
		DetourRestoreAfterWith();

		// Begin the detour transaction.
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// Hook the memory allocator.
		DetourAttach((void**)&huMemAllocHelper, Hook_huMemAllocHelper);

		// Hook the ui init function.
		DetourAttach((void**)&uiInitProcHookAddress, Hook_uiInitProc);

		// Hook the ui worker dispatch function to call the worker routine directly.
		DetourAttach((void**)&uiInitDispatchWorkerAddress, uiInitDoWorkAddress);

		// Hook the main menu and music update functions.
		DetourAttach((void**)&MusicTick, Hook_MusicTick);
		DetourAttach((void**)&MainMenuUpdate, Hook_MainMenuUpdate);

		// Setup hooks.
		huProc_InstallHooks();

		// Commit the transaction.
		if (DetourTransactionCommit() != NO_ERROR)
		{
			// Failed to hook into the process, terminate.
			TerminateProcess(GetCurrentProcess(), 0xBAD0C0DE);
		}

		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

