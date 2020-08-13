// SwampLauncher.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <string>
#include <stdio.h>
#include <detours.h>

int main(int argc, char **argv)
{
	STARTUPINFO StartupInfo = { 0 };
	PROCESS_INFORMATION ProcInfo = { 0 };

	// Initialize the startup info structure.
	StartupInfo.cb = sizeof(STARTUPINFO);

	// Build our list of dlls to inject.
	LPCSTR DllsToInject[1] =
	{
		"Swampy.dll"
	};

	// Create the game process and inject our dll into it.
	if (DetourCreateProcessWithDllsA("FrogADV.exe", GetCommandLineA(),
		NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcInfo, 1, DllsToInject, NULL) == FALSE)
	{
		// Failed to create the game process.
		printf("Failed to create game process %d!\n", GetLastError());
		MessageBox(NULL, "FrogADV.exe or Swampy.dll is missing!\nPlease place SwampLauncher.exe and Swampy.dll into the game folder and try again.", "Missing files", MB_OK);
		return 0;
	}

	// Resume the process.
	ResumeThread(ProcInfo.hThread);

	// Wait for the child process to exit (only needed for debugging).
	if (IsDebuggerPresent() == TRUE)
		WaitForSingleObject(ProcInfo.hProcess, INFINITE);

	// Close the process and thread handles.
	CloseHandle(ProcInfo.hProcess);
	CloseHandle(ProcInfo.hThread);

	return 0;
}
