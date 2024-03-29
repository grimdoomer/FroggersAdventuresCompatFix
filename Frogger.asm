; Frogger's Adventures: The Rescue [Windows 10 Patch]
; Authors: Grimdoomer, Kneesnap

; Kneesnap's Notes.
; XePatcher is a pretty neat tool, even if it's a hackjob. I think having the patch in this format will make it easier to change, but also keep it documented.
;
; I have a few things I learned which I wanted to jot down here, maybe they'll be useful to someone, but mainly it's here because I don't want to forget what I've learned. 
; 
; Notes:
;  - Instruction encoding matters. If something doesn't work, find the instruction where something went wrong, and determine if it was because the instruction wasn't encoded the way it was expected to be, and may have taken too many (or too few) bytes.
;
; This patch uses XePatcher. XePatcher assembles this file into an ELF binary, then parses it.
; We have to use "dd" or "define dword" for each block we'd like to replace. It's because XePatcher reads that value (start address + byte size) in order to determine how to actually apply the patch.
; One drawback to this approach is that XePatcher can't use call or jmp without moving the pointer to something into a register.
; The reason for this is that XePatcher turns this into a binary, and since call + jmp are relative, it isn't able to accurately determine the place to jump to.

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
; The game normally is allocating memory on the stack to a fixed size buffer. Unfortunately, the problem is that if the stack gets too large, it will 
; While this worked in Windows XP SP2, the DirectX call stack increased significantly, blowing past the original stack allocation size.
; There's no reason it can't be allocated on the heap, so all we do is change it to instead allocate on the heap.
; We never cleanup this memory, so technically it's a memory leak, but it's only allocating something like 32 - 96KB once on startup, so it's probably fine.
; This memory is actually used for something else now. Before, this would be used as stack space. It's repurposed now to contain thread information.
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
; This is problematic for the uiInit task, because UI-related stuff should always be run on the main thread due to design choices of the Windows APIs.
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
; The game has a coroutine system to manage game tasks.
; The problem is they wanted to create a stack for each "thread". (Thread here does not refer to the OS-level thread, because the game only ever had one thread, but rather a coroutine thread.)
; Our solution is to completely re-implement the system using actual threads, because that lets each task keep its own execution context (registers, etc), pause / unpause easily, etc, and have its own stack.
; We suspect the reason actual threads were not originally used is because the game needed to run on Gamecube, PS2, and Xbox, and so it was likely simpler to just hack something together when most of those systems didn't have any kind of threading support.
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
	fadd dword [g_DeltaTime]
	fst dword [g_DeltaTimeCounter]
	
	; if (g_DeltaTimeCounter < 1000 / 60) (If there's been enough time for the next update. 60 updates a second.)
	fcomp dword [005BF580h] ; This is the pointer to where the game keeps the value of how much time an update should take.
	fnstsw ax ; Fancy floating point instruction to test if the value is less than something.
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
; This overwrites a function which was called before, but was empty. It was setup at a very convenient position. Our code sets up a worker thread for a given task.
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
; This in-effect achieves the same functionality as the original system, but without using any undefined behaviour.
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
; Somehow, disabling this temporarily actually makes the game load. It was never determined why this works, it just happened to work, and we left it at that.
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
	dummy_code_to(41D69Dh, 41D6A2h, _enable_fpscap_start, _enable_fps_nop_start) ; Make sure we got rid of the entire instruction that was here before.
_enable_fpscap_end:

; Disables a limit which would make the make run too fast past 1000 FPS.
; Theoretically the game may experience issues the closer the frame value gets to the maximum digits a floating point number can store, however if that ever happens (it probably won't) just use a FPS cap.
; The FPS cap can be enabled in the block above by changing eax to 0 instead of 1.
; The patch is compatible with doing that.
%define DisableMaxFPSStart 41D76Bh
dd DisableMaxFPSStart - ExecutableBaseAddress
dd (_disable_maxfps_end - _disable_maxfps_start)
_disable_maxfps_start:
	dummy_code_to(DisableMaxFPSStart, 41D782h, _disable_maxfps_start, _disable_maxfps_start)
_disable_maxfps_end:

; The game is weird.
; It was totally built in a way which could have made it run with no frame limit with minimal code changes, and it looks like they wanted to make the game work that way.
; This makes me think the game's delta-time handling just wasn't finished or they forgot about it, so they just capped the game to 60FPS.
; This code here (Along with some changes in Hook_MainLoop) allow the game to run properly above 60FPS.

; However, there are some known issues which is why we don't enable this by default for releases.
; - Lighting in the fire levels doesn't render every frame. My guess is they decided to make the lighting render in an tick-bound update function somewhere.
; - Fire boss lightning doesn't get shown at the right position / rotation. It seems it gets stuck? 
; - There's probably some more subtle timing-related issues for bosses and enemies which might be harder to spot without looking very closely.

; The idea of the fix here is that the game does track delta-time, it's just that it needs to only run the update function 60 times a second, when it can run the render function unlimited times per second.
; So, we just switch out which delta-time is used depending on which function we call, and limit the number of times update can be called.
; It's surprising how well this works, despite the issues.

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
