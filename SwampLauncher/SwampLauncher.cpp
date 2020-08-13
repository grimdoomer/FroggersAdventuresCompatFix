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
	std::string sUtilityDrive;

	// Check the number of arguments are correct.
	if (argc != 3)
	{
		// Print the command line arguments.
		printf("SwampLauncher.exe <game exe path> <swampy.dll path>\n");
		return 0;
	}

	// Initialize the startup info structure.
	StartupInfo.cb = sizeof(STARTUPINFO);

	// Build our list of dlls to inject.
	LPCSTR DllsToInject[1] =
	{
		argv[2]
	};

	// Create the game process and inject our dll into it.
	if (DetourCreateProcessWithDllsA(argv[1], GetCommandLineA(),
		NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcInfo, 1, DllsToInject, NULL) == FALSE)
	{
		// Failed to create the game process.
		printf("Failed to create game process %d!\n", GetLastError());
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
