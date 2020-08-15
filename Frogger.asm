; Frogger's Adventures: The Rescue [Windows 10 Patch]
; Authors: Grimdoomer, Kneesnap

; Kneesnap's Notes.
; XePatcher is a pretty neat tool, even if it's a hackjob. I think having the patch in this format will make it easier to change, but also keep it documented.
;
; I have a few things I learned which I wanted to jot down here, maybe they'll be useful to someone, but mainly it's here because I don't want to forget what I've learned. 
; 
; Ghidra Notes:
;  - Instruction encoding matters. If something doesn't work, find the instruction where something went wrong, and determine if it was because the instruction wasn't encoded right.
;  - It's very easy to unbalance the stack. I should always check the stack to make sure it's good if the instruction pointer turns into something bizarre.
;  - Hex editing assembly into a binary sucks. From now on, if when making changes in Ghidra, make sure to keep my workspace setup so I can at any time export an executable from Ghidra.
;
; The way XePatcher works is that it actually assembles this file into an ELF binary, then it reads the binary. This is by we have to use "dd" to "define dword" for each block. It's because XePatcher reads that value (start address + byte size) to apply the patch.
; This is kind of out of nowhere, but I think it'd be awesome to make a Ghidra plugin that would let you take two binaries of the same file size, and auto-diff them + generate a .asm file. This is because it's much easier to make changes inside of Ghidra due to it being interactive with one drawback, being that you can't easily move code around. If it were possible to export / import in terms of a .asm file, it would make stuff that much easier.
; XePatcher can't use call or jmp without moving the pointer to something into a register. The reason for this is that XePatcher turns this into a binary, and since call + jmp are relative, it isn't able to accurately determine the place to jump to.
; Again, another reason why I should look into making a ghidra plugin for this.

; Documentation of the original .exe patch we created with a hex editor: (This is most likely no longer relevant.)
; 0x14E27 - Call our Hook_UselessFucntion function instead, which sets up thread information for the created task.
; 0x1C6B0 - Call hook destroy task.
; 0x1C8F5 - Delete code having to do with setjmp.
; 0x1C932 - Nop some more code.
; 0x1C9F9 - Call WorkerHook.
; 0x1D016 - Prevent setting the performance counter we hijack to use as the thread id to zero.
; 0x1D69D - Enable the FPS-cap.
; 0x1D79B - Disable the code which writes to the other perf variable, so we can use that memory for the thread id.
; 0xDA45A - Patch the instruction which pushes a ptr to MainMenuUpdate to the stack to instead push our main menu update hook.
; 0x13830B - Call our SetupMainThreadId function instead of the function it called before which always returned 1.
; 0x1383B4 - Call our music tick hook, instead of music tick directly.
; 0x15f668 - Set g_MainThreadId to zero. The code that was here before is not meaningful, so it can be removed without issue.
; 0x1BE454 - Hook_huProc_UselessTaskCreateFunc. This overwrites a function which was called before, but was empty. It sets up a worker thread for a given task.
; 0x1BE4B1 - Hook_huProc_SwitchTask. This overwrites the original huProc_SwitchTask completely. When the main thread calls it, it will just run the task worker, but when another thread calls it, it will put the thread to sleep until it's time to work again, and resume the main thread.
; 0x1BE580 - WorkerHook - This is called when it's time to switch to a task. This is what sleeps the main thread, and tells the worker thread to start working.
; 0x1BE5EA - SetupMainThreadId. This puts the id of the main thread into g_MainThreadId, or 0x0213f16c, which is the repurposed performance counter.
; 0x1BE600 - Hook_DestroyTask. This is called when the game wants to destroy a task. We handle this by telling the worker thread to sleep, then destroying the thread.
; 0x1BE670 - Hook_MusicTick. This decides whether or not the music tick should be called, and then calls it. We don't call the music tick function before the main menu loads, because for whatever reason that makes the game not load.
; 0x1BE686 - Hook_MainMenuUpdate. This is what lets us track when it's time to start letting MusicTick fire.
; There are some extra bytes at the end which seemed to have just been removed from the exe when it was saved by Ghidra.
; I believe this might have been some kind of compressed SecuROM code, which is no longer used because there's a No-CD fix in the version I'm testing with.


; ////////////////////////////////////////////////////////
; ////////////////// Preprocessor Stuff //////////////////
; ////////////////////////////////////////////////////////
BITS 32
		
; Base address of the executable
%define ExecutableBaseAddress 	00400000h

; Function addresses:
%define VirtualAlloc  005BF10Ch

; Data addresses:
%define AllocationPtr  0212E968h

; This macro can take the place of the `jmp` instruction, which doesn't work with XePatcher, due to jmp being a relative instruction.
; This macro is required for XePatcher to work properly.
%macro farjump 1
  push %1 ; Another option was 'mov eax, %1', 'jmp eax' which is compatible with XePatcher, but this takes up fewer bytes so we've gone with this.
  ret
%endmacro
	
%macro farcall 1
   mov eax, %1
   call eax
%endmacro

; Gets the real pointer of a new function which we have created ourselves.
%define get_our_func_ptr(func_label) (NewCodeBlockStart + func_label - _new_code_start)

; Allows easily noping code to a given address.
%define dummy_code_to(start_address, end_address, start_label, current_label) times (end_address - start_address) - (current_label - start_label) db 0x90

; ////////////////////////////////////////////////////////
; Change the stack alloc function to use malloc.
; The game normally is allocating memory on the stack, abusing undefined behavior. While this worked in Windows XP SP2, that behavior was no longer functional after that.
; This is the reason for the first crash.
; There's no reason it can't be allocated on the heap, so all we do is change it to instead allocate on the heap.
; We never cleanup this memory, so technically it's a memory leak, but it's only allocating something like 32 - 96KB once on startup, so it's probably fine.
; ////////////////////////////////////////////////////////
dd 0415141h - ExecutableBaseAddress
dd (_func_end - _func_start)
_func_start:

	; Allocate memory.
	push	4			; PAGE_READWRITE
	push	01000h		; MEM_COMMIT
	push	dword [esp+4+8]		; Allocation size
	push	0			; Allocation address
	mov		eax, dword [VirtualAlloc]
	call	eax
	
	; Check if the allocation pointer has been setup yet or not.
	cmp		dword [AllocationPtr], 0
	jnz		_done
	
	; Set the allocation pointer.
	mov		dword [AllocationPtr], eax
	
_done:
	; Return
	ret
	
_func_end:

; ////////////////////////////////////////////////////////
; Don't switch stack pointers for proc call
; ////////////////////////////////////////////////////////
dd 4128A1h - ExecutableBaseAddress
dd (_func_end_2 - _func_start_2)
_func_start_2:

	mov		esp, ebp
	pop		ebp
	ret
	
_func_end_2:

; ////////////////////////////////////////////////////////
; Call the uiInit task on the main thread.
; Since our replacement coroutine system uses threads, it means the worker tasks will be run on different threads.
; This is problematic for the uiInit task, because UI-related stuff should always be run on the main thread.
; Because of this, we're taking the uiInit task out of the task system and putting it on the main thread instead.
; ////////////////////////////////////////////////////////

dd 4127E0h - ExecutableBaseAddress
dd (_func_end_3 - _func_start_3)
_func_start_3:

	farjump(412847h)

_func_end_3:

; ////////////////////////////////////////////////////////
; New Code, written for the patch.
; This code resides in executable memory which was previously unused.
;
; Most of this code is here to implement our replacement coroutine system.
; The game has a coroutine system (look it up) to manage game tasks, which is awesome. Coroutines are great for games.
; The problem is that they created the coroutine system using setjmp and longjmp. By itself, that's fine, but the problem was it was trying to use memory which wasn't marked as stack memory as stack memory, which... caused a crash.
; Our solution is to completely re-implement the system using threads, because that lets each task keep its own execution context (registers, etc), pause / unpause easily, etc.
; 
; ////////////////////////////////////////////////////////
%define CreateEventA 005BF030h
%define CreateThread 005BF054h
%define ExitThread 005BF02Ch
%define GetCurrentThreadId 005BF0F8h
%define ResetEvent 005BF0F0h
%define SetEvent 005BF068h
%define WaitForSingleObject 005BF034h

%define huProc_TaskCreate 00414E27h ; also known as huProc_UselessTaskCreateFunc
%define huProc_SwitchTask 0041C7D5h
%define huProc_DestroyTask 0041C628h
%define huProc_TaskWorker 0041C856h
%define MusicTick 0041DBD7h
%define MainMenuUpdate 004DA72Eh
%define CheckIfGameCanStart 0040D76Dh
%define CalculateDeltaTime 0041D697h

%define PreLogicUpdate 0041BF9Dh ; These functions are used in the main loop.
%define GameRenderUpdate 0041D7C4h
%define FUN_0041303e 0041303Eh

%define g_SoundState 02139A98h ; The memory we use to store if we should be ticking sound or not.
%define g_MainThreadId 02139A9Ch ; The memory location we're using to store the main thread id.
%define g_huProcCurrentTask 0213F184h ; The pointer to the current task.
%define g_DeltaTime 0213F180h
%define g_DeltaTimeCounter 0213F16Ch

%define NewCodeBlockStart 005BE454h

dd NewCodeBlockStart - ExecutableBaseAddress
dd (_new_code_end - _new_code_start)
_new_code_start:

Hook_MainLoop:
; This is a slightly modified recreation of the main loop.
	push ebp
	mov ebp, esp
	
	; g_DeltaTimeCounter += g_DeltaTime;
	fld dword [g_DeltaTimeCounter]
	fadd dword [g_DeltaTime] ; TODO: Have to use this timer as the comparison.
	fst dword [g_DeltaTimeCounter]
	
	; if (g_DeltaTimeCounter < 1000 / 60) (If there's been enough time for the next update. 60 updates a second.)
	fcomp dword [0x005bf580] ; This is the pointer to where the game keeps the value of how much time an update should take.
	fnstsw ax ; Yeah I barely understand how this tests if the value is smaller either.
	test ah, 5h
	jnp _loop_skip_worker
	
	push dword [g_DeltaTime] ; Preserve the per-frame delta-time for later, because updating the frame will need that value.
	mov eax, dword [g_DeltaTimeCounter]
	mov dword [g_DeltaTime], eax
	mov dword [g_DeltaTimeCounter], 0 ; Reset delta-time counter.
	
	farcall(PreLogicUpdate) ; Seems to do certain tasks like keyboard update.
	
	push 0x1
	farcall(huProc_TaskWorker)
	add esp, 0x4
	
	; Restore original g_DeltaTime
	pop eax
	mov dword [g_DeltaTime], eax
	
_loop_skip_worker:

	push 0x1
	farcall(GameRenderUpdate)
	add esp, 0x4
	
	call Hook_MusicTick
	farcall(FUN_0041303e) ; Releases some sephamore.
	
	mov esp, ebp
	pop ebp
	ret

align 4, db 0
Hook_huProc_TaskCreate:
; This overwrites a function which was called before, but was empty. It sets up a worker thread for a given task.
	push ebp
	mov ebp, esp
	
	; pStackBuffer->hWorkerRunEvent = CreateEventA(NULL, TRUE, FALSE, NULL)
	push 00000000h
	push 00000000h
	push 00000001h
	push 00000000h
	call dword [CreateEventA] ; CreateEventA(NULL, TRUE, FALSE, NULL)
	mov ecx, dword [ebp + 0x8] ; get pStackBuffer
	mov dword [ecx + 8],EAX ;  pStackBuffer->hWorkerRunEvent = eax
	
	;pStackBuffer->hWorkerSleepEvent = CreateEventA(NULL, TRUE, TRUE, NULL)
	push 00000000h
	push 00000001h
	push 00000001h
	push 00000000h
	call dword [CreateEventA] ; CreateEventA(NULL, TRUE, TRUE, NULL)
	mov ecx, dword [ebp + 0x8] ; get pStackBuffer
	mov dword [ecx + 12],EAX ;  pStackBuffer->hWorkerSleepEvent = eax
	
	; pStackBuffer->hThread = CreateThread(NULL, 0, huProc_ThreadWorker, pStackBuffer, 0, pStackBuffer->pThreadId);
	push dword [ECX + 4] ; pStackBuffer->pThreadId
	push 00000000h
	push ecx ; pStackBuffer
	push get_our_func_ptr(huProc_ThreadWorker)
	push 00000000h
	push 00000000h
	call dword [CreateThread] ; CreateThread(NULL, 0, huProc_ThreadWorker, pStackBuffer, 0, pStackBuffer->pThreadId);
	mov ecx, dword [ebp + 8] ; pStackBuffer
	mov dword [ecx], eax ; pStackBuffer->hThread = eax
	
	mov esp, ebp
	pop ebp
	ret

align 4, db 0
Hook_huProc_SwitchTask:
; This overwrites the original huProc_SwitchTask completely. When the main thread calls it, it will just run the task worker, but when another thread calls it, it will put the thread to sleep until it's time to work again, and resume the main thread.
	push ebp
	mov ebp, esp
	
	; if (g_MainThreadId == GetCurrentThreadId())
	call dword [GetCurrentThreadId]
	mov ecx, dword [g_MainThreadId]
	cmp ecx, eax
	jnz huProc_switchTask_workerThreadHandling

	; huProc_TaskWorker(1)
	push 00000001h
	farcall(huProc_TaskWorker)
	
	; return
	add esp, 0x4 ; Unnecessary since we're about to replace the stack variable, but good for practice purposes.
	mov esp, ebp
	pop ebp
	ret
	
huProc_switchTask_workerThreadHandling:
	push esi ; We're going to use ESI to store g_huProcCurrentTask because it's non-volatile. There's a race condition which can happen if we access g_huProcCurrentTask after calling SetEvent, so we definitely want to keep it.
	mov esi, dword [g_huProcCurrentTask]
	test esi, esi
	jz huProc_switchTask_workerExit ; Return if g_huProcCurrentTask is null.
	mov dx, word [esi + 72] ; Get flags.
	shr dx, 2
	and dx, 0xFF
	cmp dx, 4
	jz huProc_switchTask_workerExit ; Return if (g_huProcCurrentTask->flags >> 2 & 0xff) == 4
	
	; g_huProcCurrentTask->flags = g_huProcCurrentTask->flags & 0xfc03 | 8;
	mov dx, word [esi + 72] ; Get flags
	and edx, 0xFC03 ; Intentionally working on the extended (32-bit) register.
	or dx, 0x8
	mov word [esi + 72], dx ; Store flags value.
	
	; g_huProcCurrentTask->taskStatus = param_1
	mov edx, dword [ebp + 8]
	mov dword [esi + 84], edx
	
	; ResetEvent(g_huProcCurrentTask->stackAllocation->hWorkerRunEvent);
	mov edx, dword [esi + 100] ; g_huProcCurrentTask->stackAllocation
	push dword [edx + 8] ; stackAllocation->hWorkerRunEvent
	call dword [ResetEvent]
	
	; SetEvent(g_huProcCurrentTask->stackAllocation->hWorkerSleepEvent)
	mov edx, dword [esi + 100] ; g_huProcCurrentTask->stackAllocation
	push dword [edx + 12] ; stackAllocation->hWorkerSleepEvent
	call dword [SetEvent]
	
	; WaitForSingleObject(g_huProcCurrentTask->stackAllocation->hWorkerRunEvent, -1)
	mov edx, dword [esi + 100] ; g_huProcCurrentTask->stackAllocation
	push 0xFFFFFFFF
	push dword [edx + 8] ; stackAllocation->hWorkerRunEvent
	call dword [WaitForSingleObject]
	
huProc_switchTask_workerExit:
	pop esi ; Required to keep esi balanced.
	mov esp, ebp
	pop ebp
	ret

align 4, db 0
huProc_TaskWorkerSwitchImpl:
; This is called by huProc_TaskWorker in order to actually switch to the task.that should get run. (Also called WorkerHook)
	push esi ; Using esi to store g_huProcCurrentTask avoids a race condition. (Which reliably crashes the game.)
	mov esi, dword [g_huProcCurrentTask]
	
	; ResetEvent(g_huProcCurrentTask->stackAllocation->hWorkerSleepEvent)
	mov edx, dword [esi + 100] ; g_huProcCurrentTask->stackAllocation
	push dword [edx + 12] ; stackAllocation->hWorkerSleepEvent
	call dword [ResetEvent]
	
	; SetEvent(g_huProcCurrentTask->stackAllocation->hWorkerRunEvent)
	mov edx, dword [esi + 100] ; g_huProcCurrentTask->stackAllocation
	push dword [edx + 8] ; stackAllocation->hWorkerRunEvent
	call dword [SetEvent]
	
	; WaitForSingleObject(g_huProcCurrentTask->stackAllocation->hWorkerSleepEvent, -1);
	mov edx, dword [esi + 100] ; g_huProcCurrentTask->stackAllocation
	push 0xFFFFFFFF
	push dword [edx + 12] ; stackAllocation->hWorkerSleepEvent
	call dword [WaitForSingleObject]
	
	; g_huProcCurrentTask->flags |= 1;
	mov cx, word [esi + 72]
	or cx, 0x1
	mov word [esi + 72], cx
	
	pop esi
	ret
	
align 4, db 0
SetupMainThreadId:
; This tracks the main thread id, so we're able to determine when we're on the main thread or not.
	push ebp
	mov ebp, esp
	
	mov dword [g_SoundState], 0
	mov dword [g_DeltaTimeCounter], 0 ; Reset delta-time counter.
	
	call dword [GetCurrentThreadId]
	mov dword [g_MainThreadId], eax
	mov eax, 00000001h ; Change the return value to be 1, since that's what the original function does.
	
	mov esp, ebp
	pop ebp
	ret
	
align 4, db 0
huProc_DestroyTaskDestroyImpl:
; This is called by huProc_DestroyTask in order to actually destroy the task.
	push ebp
	mov ebp, esp
	
	; SetEvent(task->stackAllocation->hWorkerSleepEvent);
	mov ecx, dword [ebp + 8]; huTask* task
	mov eax, dword [ecx + 100]; task->stackAllocation
	push dword [eax + 12] ; stackAllocation->hWorkerSleepEvent
	call dword [SetEvent]
	
	; ExitThread(0)
	push 00000000h
	call dword [ExitThread]
	
	mov esp, ebp
	pop ebp
	ret
	
align 4, db 0
Hook_MusicTick:
; This decides whether or not the real MusicTick should be run.
; We intentionally set it to not run until after the main menu loads, because for some reason it causes the game to load at a snails pace, and crash.
; Somehow, disabling this temporarily actually makes the game load.
	push ebp
	mov ebp, esp
	
	; if (g_SoundState == 2)
	mov ecx, dword [g_SoundState]
	cmp ecx, 2
	jnz Hook_MusicTick_Exit
	farcall(MusicTick) ; MusicTick()
	
	; return
Hook_MusicTick_Exit:
	mov esp, ebp
	pop ebp
	ret
	
align 4, db 0
Hook_MainMenuUpdate:
; Calls every frame/tick on the main menu. This is what we use to track when we can enable MusicTick.
	mov eax, dword [g_SoundState]
	cmp eax, 2
	jge Hook_MainMenuUpdate_Skip ; Run the main menu update function without increasing g_SoundState, because it's already active.
	
	; g_SoundState++
	inc eax
	mov dword [g_SoundState], eax
	
	; Run the MainMenuUpdate function.
Hook_MainMenuUpdate_Skip:
	farjump(MainMenuUpdate)
	
align 4, db 0
huProc_ThreadWorker:
; This is the code which triggers the task code to run.
	push ebp
	mov ebp, esp
	
	; ResetEvent(pThreadInfo->hWorkerSleepEvent)
	mov ecx, dword [ebp + 8] ; pThreadInfo
	push dword [ecx + 12] ; pThreadInfo->hWorkerSleepEvent
	call dword [ResetEvent]
	
	; WaitForSingleObject(pThreadInfo->hWorkerRunEvent, -1)
	mov ecx, dword [ebp + 8] ; pThreadInfo
	push 0xFFFFFFFF
	push dword [ecx + 8] ; pThreadInfo->hWorkerRunEvent
	call dword [WaitForSingleObject]
	
	; g_huProcCurrentTask->pFunction()
	mov ecx, dword [g_huProcCurrentTask]
	call dword [ecx + 88] ; pFunction
	
	; huProc_DestroyTask(g_huProcCurrentTask->processId)
	mov ecx, dword [g_huProcCurrentTask]
	push word [ecx + 78] ; g_huProcCurrentTask->processId
	farcall(huProc_DestroyTask)
	add esp, 4h ; cdecl call needs stack adjustment.
	
	; huProc_SwitchTask(-1)
	push 0xFFFFFFFF
	farcall(huProc_SwitchTask)
	add esp, 4h ; cdecl call needs stack adjustment.
	
	mov esp, ebp
	pop ebp
	ret

_new_code_end:


; ////////////////////////////////////////////////////////
; Overwrite Code. All of the code here overwrites existing code.
; ////////////////////////////////////////////////////////

; This code overwrites the original huProc_TaskCreate function with Hook_huProc_TaskCreate.
dd huProc_TaskCreate - ExecutableBaseAddress
dd (_task_create_end - _task_create_start)
_task_create_start:
	farjump(get_our_func_ptr(Hook_huProc_TaskCreate))
_task_create_end:

; This code overwrites the original huProc_SwitchTask function with Hook_huProc_SwitchTask.
dd huProc_SwitchTask - ExecutableBaseAddress
dd (_switchTaskHook_end - _switchTaskHook_start)
_switchTaskHook_start:
	farjump(get_our_func_ptr(Hook_huProc_SwitchTask))
_switchTaskHook_end:

; This code replaces the original huProc_DestroyTask destroy logic with a call to huProc_DestroyTaskDestroyImpl
dd 41C6B0h - ExecutableBaseAddress
dd (_destroy_hook_end - _destroy_hook_start)
_destroy_hook_start:
	push ecx
	farcall(get_our_func_ptr(huProc_DestroyTaskDestroyImpl))
	; add esp, 0x4 ; This would be good to have, but esp is overwritten on the next instruction 'mov esp, ebp', and since we're limited on space, I'm omitting it.
_destroy_hook_nop_start:
	dummy_code_to(41C6B0h, 41C6BCh, _destroy_hook_start, _destroy_hook_nop_start)
_destroy_hook_end:

; Calls SetupMainThreadId on setup.
dd CheckIfGameCanStart - ExecutableBaseAddress
dd (_enable_setup_end - _enable_setup_start)
_enable_setup_start:
	farjump(get_our_func_ptr(SetupMainThreadId))
_enable_setup_end:

; Calls Replaces the call to MainMenuUpdate with a call to the hook.
dd 4DA459h - ExecutableBaseAddress
dd (_enable_menu_end - _enable_menu_start)
_enable_menu_start:
	push dword get_our_func_ptr(Hook_MainMenuUpdate)
_enable_menu_end:

;//////////////////////////
; huProc_TaskWorker Changes
;//////////////////////////
%define huProc_TaskWorker_Start1 41C8F5h
dd huProc_TaskWorker_Start1 - ExecutableBaseAddress
dd (huProc_TaskWorker_nop1_end - huProc_TaskWorker_nop1_start)
huProc_TaskWorker_nop1_start:
	dummy_code_to(huProc_TaskWorker_Start1, 41C935h, huProc_TaskWorker_nop1_start, huProc_TaskWorker_nop1_start)
huProc_TaskWorker_nop1_end:

; Call the worker hook.
%define huProc_TaskWorker_Start2 41C9F9h
dd huProc_TaskWorker_Start2 - ExecutableBaseAddress
dd (huProc_TaskWorker_callhook_end - huProc_TaskWorker_callhook_start)
huProc_TaskWorker_callhook_start:
    farcall(get_our_func_ptr(huProc_TaskWorkerSwitchImpl))
huProc_Taskworker_nop3_start:
	dummy_code_to(huProc_TaskWorker_Start2, 41CA07h, huProc_TaskWorker_callhook_start, huProc_Taskworker_nop3_start)
huProc_TaskWorker_callhook_end:

; Frame-rate / Game Timer Fixes:
; Allows the game to run at an uncapped frame-rate.

; Ensures the the FPS-cap is disabled.
dd 41D69Dh - ExecutableBaseAddress
dd (_enable_fpscap_end - _enable_fpscap_start)
_enable_fpscap_start:
    mov eax, 00000001h
_enable_fps_nop_start:
	dummy_code_to(41D69Dh, 41D6A2h, _enable_fpscap_start, _enable_fps_nop_start)
_enable_fpscap_end:

; The game is weird.
; It was totally built in a way which could have made it run with no frame limit with minimal code changes, and it looks like they wanted to make the game work that way.
; In fact, the previous game, Frogger Beyond, did work without a frame limit just fine, and it was made by the same team.
; This makes me think the game's delta-time handling just wasn't tested and they forgot to finish it.
; This code here (Along with some changes in Hook_MainLoop) allow the game to run perfect above 60FPS.
; It's very likely the game would break at over 1000FPS, but mainly because it has an upper limit. I should remove that upper limit later.
; 1000FPS is way beyond anything we need to support though, so it's probably fine, people can limit to 1000 FPS if they really want.
; I think the theoretical limit for the game working is when a 32-bit float single stops being precise enough to accurately handle the time each frame is taking.
; However, this is quite beyond the limit of what the human eye can see (hell, 1000FPS is way past that) so it certainly doesn't matter.

; The idea of the fix here is that the game does track delta-time, it's just that it needs to only run the update function 60 times a second, when it can run the render function unlimited times per second.
; So, we just switch out which delta-time is used depending on which function we call, and limit the number of times update can be called.
; I'm actually amazed it was this simple.

%define MainLoop_HookerStart 538396h
dd MainLoop_HookerStart - ExecutableBaseAddress
dd (_mainloop_hooker_end - _mainloop_hooker_start)
_mainloop_hooker_start:
	farcall(get_our_func_ptr(Hook_MainLoop))
_mainloop_hooker_nop:
	dummy_code_to(MainLoop_HookerStart, 5383C3h, _mainloop_hooker_start, _mainloop_hooker_nop)
_mainloop_hooker_end:


; This disables some code which writes to an unused delta counter variable. We're going to hijack this variable and use it for our delta-time counter, but to do this we gotta remove this code here which would interfere with our value. (The variable in question is g_DeltaTimeCounter)
%define DeltaTimeOverwriteVar 41D78Ah
dd DeltaTimeOverwriteVar - ExecutableBaseAddress
dd (_perf_disableoldctr_end - _perf_disableoldctr_start)
_perf_disableoldctr_start:
	dummy_code_to(DeltaTimeOverwriteVar, 41D7A9h, _perf_disableoldctr_start, _perf_disableoldctr_start)
_perf_disableoldctr_end:

; ////////////////////////////////////////////////////////
; //////////////////// End of file ///////////////////////
; ////////////////////////////////////////////////////////
dd -1 ; XePatcher marker that there are no more code bodies.
end