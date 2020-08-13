/*

*/

#include "huProc.h"
#include <detours.h>

// Trampolines:
void(__cdecl *huProc_UselessTaskCreateFunc)(void *pStackBuffer) = (void(__cdecl*)(void*))0x414E27;
void(__cdecl *huProc_SwitchTask)(DWORD TaskStatus) = (void(__cdecl*)(DWORD))0x0041C7D5;
void(__cdecl *huProc_DestroyTask)(WORD ProcessId) = (void(__cdecl*)(WORD))0x0041C628;
void(__cdecl *huProc_TaskWorker)(int StatusValue) = (void(__cdecl*)(int))0x0041C856;

huTask*(__cdecl *huProc_GetProcessById)(WORD ProcessId) = (huTask*(__cdecl*)(WORD))0x0041CB6F;
void(__cdecl *huProc_CleanupTask)(huTask *pProcess) = (void(__cdecl*)(huTask*))0x0041CA24;

void(__cdecl *huHeapFree)(void *pAddress) = (void(__cdecl*)(void*))0x00414B39;

void(__cdecl *PrintDbgString)(const char *psFormat, ...) = (void(__cdecl*)(const char*, ...))0x0040FD68;

huTask **g_huProcTopTask = (huTask**)0x0212E9E0;
huTask **g_huProcBottomTask = (huTask**)0x0212E9DC;

huTask **g_huProcCurrentTask = (huTask**)0x0213F184;
huTask **g_huProcNextTask = (huTask**)0x0212E9E4;

huTask **g_RegisterBlockBase = (huTask**)0x0212EA28;

// Forward declarations:
void __cdecl Hook_huProc_UselessTaskCreateFunc(void *pStackBuffer);
void __cdecl Hook_huProc_SwitchTask(DWORD TaskStatus);
void __cdecl Hook_huProc_DestroyTask(WORD ProcessId);
void __cdecl Hook_huProc_TaskWorker(int StatusValue);

DWORD g_MainThreadId = GetCurrentThreadId();

void huProc_InstallHooks()
{
	// Setup hooks.
	DetourAttach((void**)&huProc_UselessTaskCreateFunc, Hook_huProc_UselessTaskCreateFunc);
	DetourAttach((void**)&huProc_SwitchTask, Hook_huProc_SwitchTask);
	DetourAttach((void**)&huProc_DestroyTask, Hook_huProc_DestroyTask);
	DetourAttach((void**)&huProc_TaskWorker, Hook_huProc_TaskWorker);
}

DWORD huProc_ThreadWorker(huTaskThreadInfo *pThreadInfo)
{
	// Reset the sleep function so huProc knows we are asleep.
	ResetEvent(pThreadInfo->hWorkerSleepEvent);

	// Sleep and wait for the work signal.
	WaitForSingleObject(pThreadInfo->hWorkerRunEvent, INFINITE);

	// Call the worker function, this will either call SwitchTask() or DestroyTask, either way we will catch
	// both and handle accordingly.
	(*g_huProcCurrentTask)->pFunction();

	// Destroy the task.
	huProc_DestroyTask((*g_huProcCurrentTask)->ProcessId);

	// Switch task in case destroy task did not kill us.
	huProc_SwitchTask(0xFFFFFFFF);
	return 0;
}

void __cdecl Hook_huProc_UselessTaskCreateFunc(void *pStackBuffer)
{
	// Treat the stack buffer as storage for thread info.
	huTaskThreadInfo *pThreadInfo = (huTaskThreadInfo*)pStackBuffer;

	// Create the thread worker events.
	pThreadInfo->hWorkerRunEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	pThreadInfo->hWorkerSleepEvent = CreateEventA(NULL, TRUE, TRUE, NULL);
	if (pThreadInfo->hWorkerRunEvent == NULL || pThreadInfo->hWorkerSleepEvent == NULL)
	{
		// Failed to create thread worker events.
		OutputDebugString(L"Hook_huProc_UselessTaskCreateFunc(): failed to create thread worker events!\n");
		DebugBreak();
	}

	// Create the worker thread.
	pThreadInfo->hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)huProc_ThreadWorker, pThreadInfo, NULL, &pThreadInfo->ThreadId);
	if (pThreadInfo->hThread == NULL)
	{
		// Failed to create worker thread.
		OutputDebugString(L"Hook_huProc_UselessTaskCreateFunc(): failed to create worker thread!\n");
		DebugBreak();
	}
}

void __cdecl Hook_huProc_SwitchTask(DWORD TaskStatus)
{
	// Prohibit the main thread from running switch task.
	if (GetCurrentThreadId() == g_MainThreadId)
	{
		Hook_huProc_TaskWorker(1);
		return;
	}

	//PrintDbgString("huProc_SwitchTask: ProcID=%d TaskStatus=0x%08x\n", (*g_huProcCurrentTask)->ProcessId, TaskStatus);

	// Get the task that is currently executing.
	huTask *pCurrentTask = *g_huProcCurrentTask;
	if (pCurrentTask == nullptr)
		return;

	// Check some flag value.
	if (((pCurrentTask->Flags >> 2) & 0xFF) == 4)
		return;

	// Update flag values.
	pCurrentTask->Flags = (pCurrentTask->Flags & 0xFC03) | 8;

	// Set the task status value.
	pCurrentTask->TaskStatus = TaskStatus;

	// Get the thread info block for easy access.
	huTaskThreadInfo *pThreadInfo = (huTaskThreadInfo*)pCurrentTask->StackAllocation;

	// Reset the run worker event.
	ResetEvent(pThreadInfo->hWorkerRunEvent);

	// Signal the sleep event so huProc knows to schedule the next task.
	SetEvent(pThreadInfo->hWorkerSleepEvent);

	// Sleep until we are signaled for more work.
	WaitForSingleObject(pThreadInfo->hWorkerRunEvent, INFINITE);
}

void __cdecl Hook_huProc_DestroyTask(WORD ProcessId)
{
	//PrintDbgString("huProc_DestroyTask: ProcID=%d ProcessId=%d\n", (*g_huProcCurrentTask)->ProcessId, ProcessId);

	// Get the huTask block for the specified process id.
	huTask *pTask = huProc_GetProcessById(ProcessId);
	if (pTask == nullptr)
	{
		// Illigal process id, which is slightly worse than an illegal process id.
		PrintDbgString("huPROC:Illigal proc ID=%d\n", ProcessId);
		return;
	}

	// Make sure this is not the top or bottom process.
	if (pTask == *g_huProcTopTask || pTask == *g_huProcBottomTask)
	{
		PrintDbgString("huPROC:Don't destroy proc Top & bottom");
		return;
	}

	// Check for some flag value.
	if (((pTask->Flags >> 2) & 0xFF) == 4)
		return;

	// Cleanup the process (this does not free the stack allocation we store the thread info block in).
	huProc_CleanupTask(pTask);

	// Check if the task we are destroying is the current task.
	if (pTask == *g_huProcCurrentTask)
	{
		// Get the thread info block for the task.
		huTaskThreadInfo *pThreadInfo = (huTaskThreadInfo*)pTask->StackAllocation;

		// Signal the sleep event so huProc knows to schedule the next task.
		SetEvent(pThreadInfo->hWorkerSleepEvent);

		// Terminate the thread.
		ExitThread(0);
	}
}

void __cdecl Hook_huProc_TaskWorker(int StatusValue)
{
	//PrintDbgString("huProc_TaskWorker: StatusValue=%d\n", StatusValue);
	//huProc_TaskWorker(StatusValue);
	//return;

	// Cleanup resources from any terminiated threads.
	huTask *pTask = *g_RegisterBlockBase;
	for (int i = 0; i < 8; i++)
	{
		// Check if the task has terminated.
		if (((pTask[i].Flags >> 1) & 1) != 0)
		{
			// Free the stack allocation for the task.
			huHeapFree(pTask[i].StackAllocation);
			pTask[i].StackAllocation = nullptr;

			// Mask out some flag value.
			pTask[i].Flags &= 0xFFFD;
		}
	}

	// Loop and run tasks.
	for (*g_huProcNextTask = *g_RegisterBlockBase; *g_huProcNextTask != nullptr; *g_huProcNextTask = (*g_huProcNextTask)->pFLink)
	{
		// Set the currently running task.
		*g_huProcCurrentTask = *g_huProcNextTask;
		huTask *pTask = *g_huProcCurrentTask;

		// Check some flag value.
		DWORD flagValue = (pTask->Flags >> 2) & 0xFF;
		if (flagValue == 2 && pTask->TaskStatus >= 0)
		{
			// Update the task status value.
			pTask->TaskStatus -= StatusValue;
			if (pTask->TaskStatus > 0)
				continue;

			// Reset task status and change some flag value.
			pTask->TaskStatus = 0;
			pTask->Flags = (pTask->Flags & 0xFC03) | 4;
		}
		else if (flagValue != 1)
		{
			continue;
		}

		// Get the thread info block for the task.
		huTaskThreadInfo *pThreadInfo = (huTaskThreadInfo*)pTask->StackAllocation;

		// Reset the sleep event.
		ResetEvent(pThreadInfo->hWorkerSleepEvent);

		// Signal the worker to wake up and do work.
		SetEvent(pThreadInfo->hWorkerRunEvent);

		// Sleep until the worker is done.
		WaitForSingleObject(pThreadInfo->hWorkerSleepEvent, INFINITE);

		// Set some flag value on the currently running task.
		(*g_huProcCurrentTask)->Flags |= 1;
	}

	*g_huProcCurrentTask = nullptr;
}