
#include <Windows.h>
#include "cpp_security.hpp"
#include <cstdio>
#include <functional>
#include <vector>

//checks the process environment block (peb) for a "beingdebugged" field (gets set if process is launched in a debugger)
//possible bypass: once the peb byte is set, set the value to 0 before the application checks
int security::internal::memory::being_debugged_peb() {
	BOOL found = FALSE;
	_asm
	{
		xor eax, eax;			//clear the eax register
		mov eax, fs: [0x30] ;	//reference start of the process environment block
		mov eax, [eax + 0x02];	//beingdebugged is stored in peb + 2
		and eax, 0x000000FF;	//reference one byte
		mov found, eax;			//copy value to found
	}

	//if found is true, we return the right code.
	if (found) { return security::internal::debug_results::being_debugged_peb; }
}

//checks if a debugger is running (in another system/process)
//possible bypass: set a breakpoint before this gets called, single step, set the return value to 0
int security::internal::memory::remote_debugger_present() {
	//declare variables to hold the process handle & bool to check if it was found
	HANDLE h_process = INVALID_HANDLE_VALUE;
	BOOL found = FALSE;

	//set the process handle to the current process
	h_process = GetCurrentProcess();
	//check if a remote debugger is present
	CheckRemoteDebuggerPresent(h_process, &found);

	//if found is true, we return the right code.
	if (found) { return security::internal::debug_results::remote_debugger_present; }

	return security::internal::debug_results::none;
}

//checks if certain windows are present (not the name that can be easily changed but the window_class_name)
//possible bypass: set a breakpoint before this gets called, single step, set the return value to 0
int security::internal::memory::check_window_name() {
	//window class names
	const wchar_t* window_class_name_idapro = L"Qt5QWindowIcon"; //idapro
	const wchar_t* window_class_name_ollydbg = L"OLLYDBG";		 //ollydbg
	const wchar_t* window_class_name_ghidra = L"SunAwtFrame";    //ghidra
	const wchar_t* window_class_name_immunity = L"ID";			 //immunity debugger

	//if one is found, we return the right code.
	if (FindWindow(window_class_name_idapro, 0) || FindWindow(window_class_name_ollydbg, 0) || FindWindow(window_class_name_ghidra, 0) || FindWindow(window_class_name_immunity, 0)) {
		return security::internal::debug_results::find_window;
	}

	return security::internal::debug_results::none;
}

//another check for the peb flag, this time by the function from winapi.h
//possible bypass: set a breakpoint before this gets called, single step, set the return value to 0
int security::internal::memory::is_debugger_present() {
	//if debugger is found, we return the right code.
	if (IsDebuggerPresent()) { return security::internal::debug_results::debugger_is_present; }

	return security::internal::debug_results::none;
}

//looks for process environment block references
//they usually start with FS:[0x30h]. fs = frame segment, indicates reference to the programs internal header structures
//0x68 offset from the peb is ntglobalflag, three flags get set if a process is being debugged
//FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_FREE_CHECK (0x20), FLG_HEAP_VALIDATE_PARAMETERS(0x40)
int security::internal::memory::nt_global_flag_peb() {
	//bool to indicate find status
	BOOL found = FALSE;
	_asm
	{
		xor eax, eax;			//clear the eax register
		mov eax, fs: [0x30] ;   //reference start of the peb
		mov eax, [eax + 0x68];	//peb+0x68 points to NtGlobalFlags
		and eax, 0x00000070;	//check three flags
		mov found, eax;			//copy value to found
	}

	//if found is true, we return the right code.
	if (found) { return security::internal::debug_results::dbg_global_flag; }
}

//two checks here, 1. xxx, 2. NoDebugInherit
int security::internal::memory::nt_query_information_process() {
	HANDLE h_process = INVALID_HANDLE_VALUE;
	DWORD found = FALSE;
	DWORD process_debug_port = 0x07;	//first method, check msdn for details
	DWORD process_debug_flags = 0x1F;	//second method, check msdn for details

	//get a handle to ntdll.dll so we can use NtQueryInformationProcess
	HMODULE h_ntdll = LoadLibraryW(L"ntdll.dll");
	
	//if we cant get the handle for some reason, we return none
	if (h_ntdll == INVALID_HANDLE_VALUE || h_ntdll == NULL) { return security::internal::debug_results::none; }

	//dynamically acquire the address of NtQueryInformationProcess
	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(h_ntdll, "NtQueryInformationProcess");

	//if we cant get access for some reason, we return none
	if (NtQueryInformationProcess == NULL) { return security::internal::debug_results::none; }

	//method 1: query ProcessDebugPort
	h_process = GetCurrentProcess();
	NTSTATUS status = NtQueryInformationProcess(h_process, ProcessDebugPort, &found, sizeof(DWORD), NULL);

	//found something
	if (!status && found) { return security::internal::debug_results::nt_query_information_process; }

	//method 2: query ProcessDebugFlags
	status = NtQueryInformationProcess(h_process, process_debug_flags, &found, sizeof(DWORD), NULL);

	//the ProcessDebugFlags set found to 1 if no debugger is found, so we check !found.
	if (!status && !found) { return security::internal::debug_results::nt_query_information_process; }

	return security::internal::debug_results::none;
}

//hides the thread from any debugger, any attempt to control the process after this call ends the debugging session
int security::internal::memory::nt_set_information_thread() {
	DWORD thread_hide_from_debugger = 0x11;

	//get a handle to ntdll.dll so we can use NtQueryInformationProcess
	HMODULE h_ntdll = LoadLibraryW(L"ntdll.dll");

	//if we cant get the handle for some reason, we return none
	if (h_ntdll == INVALID_HANDLE_VALUE || h_ntdll == NULL) { return security::internal::debug_results::none; }

	//dynamically acquire the address of NtQueryInformationProcess
	_NtQueryInformationProcess NtQueryInformationProcess = NULL;
	NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(h_ntdll, "NtQueryInformationProcess");

	//if we cant get access for some reason, we return none
	if (NtQueryInformationProcess == NULL) { return security::internal::debug_results::none; }

	//make call to deattach a debugger :moyai:
	(_NtSetInformationThread)(GetCurrentThread(), thread_hide_from_debugger, 0, 0, 0);

	return security::internal::debug_results::none;
}

int security::internal::memory::debug_active_process(const char* cpid) {
	BOOL found = FALSE;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	TCHAR sz_path[MAX_PATH];
	DWORD exit_code = 0;

	CreateMutex(NULL, FALSE, L"antidbg");
	if (GetLastError() != ERROR_SUCCESS)
	{
		//if we get here, we're in the child process
		if (DebugActiveProcess((DWORD)atoi(cpid)))
		{
			//no debugger found
			return security::internal::debug_results::none;
		}
		else
		{
			//debugger found, exit child with unique code that we can check for
			exit(555);
		}
	}

	//parent process
	DWORD pid = GetCurrentProcessId();
	GetModuleFileName(NULL, sz_path, MAX_PATH);

	char cmdline[MAX_PATH + 1 + sizeof(int)];
	snprintf(cmdline, sizeof(cmdline), "%ws %d", sz_path, pid);

	//start child process
	BOOL success = CreateProcessA(
		NULL,		//path (NULL means use cmdline instead)
		cmdline,	//command line
		NULL,		//process handle not inheritable
		NULL,		//thread handle not inheritable
		FALSE,		//set handle inheritance to FALSE
		0,			//no creation flags
		NULL,		//use parent's environment block
		NULL,		//use parent's starting directory 
		&si,		//pointer to STARTUPINFO structure
		&pi);		//pointer to PROCESS_INFORMATION structure

	//wait until child process exits and get the code
	WaitForSingleObject(pi.hProcess, INFINITE);

	//check for our unique exit code
	if (GetExitCodeProcess(pi.hProcess, &exit_code) == 555) { found = TRUE; }

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	//if found is true, we return the right code.
	if (found) { return security::internal::debug_results::debug_active_process; }

	return security::internal::debug_results::none;
}

//will throw an exception when trying to close an invalid handle (only when debugged)
//so if we pass an invalid handle and get the exception, we know that we're being debugged
//possible bypass: change the passed handle to an existing handle or adjust the extended instruction pointer register to skip over the invalid handle
int security::internal::exceptions::close_handle_exception() {
	//invalid handle
	HANDLE h_invalid = (HANDLE)0xDEADBEEF;

	__try
	{
		CloseHandle(h_invalid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		//if we get the exception, we return the right code.
		return security::internal::debug_results::close_handle_exception;
	}

	return security::internal::debug_results::none;
}

//we force an exception to occur, if it occurs outside of a debugger the __except() handler is called, if it's inside a debugger it will not be called
int security::internal::exceptions::single_step_exception() {
	__try
	{
		_asm
		{
			pushfd;						//save flag register
			or byte ptr[esp + 1], 1;	//set trap flag in EFlags
			popfd;						//restore flag register
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { return security::internal::debug_results::none; }

	//if we get the exception, we return the right code.
	return security::internal::debug_results::single_step;
}

//i3 is a standard software breakcode (opcode 0xCC), when you set a breakpoint the debugger replaces the opcode under the breakpoint location with
//0xCC (int 3), when the debugger hits this opcode, it breaks and restores the original opcode (after clicking go again)
//we use an exception handler to switch found from true to false
//without the debugger, something has to handle the breakpoint exception (our handler)
//if it doesn't get hit, theres a debugger handling it instead -> we can detect that our handler was not run -> debugger found
//possible bypass: most debuggers give an option (pass exception to the application or let the debugger handle it), if the debugger handles it, we can detect it.
int security::internal::exceptions::int_3() {
	__try
	{
		_asm
		{
			int 3;	//0xCC / standard software breakpoint
		}
	}
	//exception is handled by our app = debugger did not attempt to intervene
	__except (EXCEPTION_EXECUTE_HANDLER) { return security::internal::debug_results::none; }

	//if we don't get the exception, we return the right code.
	return security::internal::debug_results::int_3_cc;
}

//2d is a kernel interrupt (opcode 0x2D), when it gets executed, windows will use the extended instruction pointer register value as the exception address,
//after then it increments the extended instruction pointer register value by 1.
//windows also checks the eax register value to dertimne how to adjust the exception address
//if the eax register is 1, 3, or 4 (on all windows version) or 5 on vista and later, it will increase the exception address by one
//here we have 2 options, first we check if we handle the exception or the debugger (same as above)
//
//after increasing the exception address windows issues an EXCEPTION_BREAKPOINT (0x80000003) exception if a debugger is present.
//some debuggers use the extended instruction pointer register to determine from where to resume execution
//some other debuggers will use the exception address as the address from where to resume execution
//this might result in a single-byte instruction being skipped (because windows increased the exception address by one) or in the
//execution of a completely different instruction because the first instruction byte is missing.
//this behaviour can be checked to see whether a debugger is present.
int security::internal::exceptions::int_2d() {
	BOOL found = false;
	__try
	{
		_asm
		{
			int 0x2D;	//kernel breakpoint
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER) { return security::internal::debug_results::none; }

	__try
	{
		__asm
		{
			xor eax, eax; //clear the eax register
			int  2dh;     //try to get the debugger to bypass the instruction
			inc  eax;     //set the eax register to 1
			mov found, eax;
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER) { return security::internal::debug_results::none; }

	//if we don't get the exception, we return the right code.
	return security::internal::debug_results::int_2;
}

int security::internal::exceptions::prefix_hop() {
	__try
	{
		_asm
		{
			__emit 0xF3;	//0xF3 0x64 is the prefix rep
			__emit 0x64;
			__emit 0xCC;	//this gets skipped over if being debugged (read security::internal::exceptions::int_3())
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER) { return security::internal::debug_results::none; }

	//if we don't get the exception, we return the right code.
	return security::internal::debug_results::prefix_hop;
}

int security::internal::timing::rdtsc() {
	//integers for time values
	UINT64 time_a, time_b = 0;
	int time_upper_a, time_lower_a = 0;
	int time_upper_b, time_lower_b = 0;

	_asm
	{
		//rdtsc stores result across EDX:EAX
		rdtsc;
		mov time_upper_a, edx;
		mov time_lower_a, eax;

		//junk code -> skip through breakpoint
		xor eax, eax;
		mov eax, 5;
		shr eax, 2;
		sub eax, ebx;
		cmp eax, ecx

		rdtsc;
		mov time_upper_b, edx;
		mov time_lower_b, eax;
	}

	time_a = time_upper_a;
	time_a = (time_a << 32) | time_lower_a;

	time_b = time_upper_b;
	time_b = (time_b << 32) | time_lower_b;

	//0x10000 is purely empirical and is based on the computer's clock cycle
	//should change depending on the length and complexity of the code between each rdtsc operation
	if (time_b - time_a > 0x10000) { return security::internal::debug_results::rdtsc; }

	return security::internal::debug_results::none;
}

//checks how much time passes between the two query performance counters
//if more than X (here 30ms) pass, a debugger is slowing execution down (manual breakpoints etc.)
int security::internal::timing::query_performance_counter() {
	LARGE_INTEGER t1;
	LARGE_INTEGER t2;

	QueryPerformanceCounter(&t1);

	//junk code
	_asm
	{
		xor eax, eax;
		push eax;
		push ecx;
		pop eax;
		pop ecx;
		sub ecx, eax;
		shl ecx, 4;
	}

	QueryPerformanceCounter(&t2);

	//30 is a random value
	if ((t2.QuadPart - t1.QuadPart) > 30) { return security::internal::debug_results::query_performance_counter; }

	return security::internal::debug_results::none;
}

//same as above
int security::internal::timing::get_tick_count() {
	DWORD t1;
	DWORD t2;

	t1 = GetTickCount();

	//junk code
	_asm
	{
		xor eax, eax;
		push eax;
		push ecx;
		pop eax;
		pop ecx;
		sub ecx, eax;
		shl ecx, 4;
	}

	t2 = GetTickCount();

	//30 ms seems ok
	if ((t2 - t1) > 30) { return security::internal::debug_results::get_tick_count; }

	return security::internal::debug_results::none;
}

int security::internal::cpu::hardware_debug_registers() {
	CONTEXT ctx = { 0 };
	HANDLE h_thread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(h_thread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			return security::internal::debug_results::hardware_debug_registers;
		}
	}
	return security::internal::debug_results::none;
}

int security::internal::cpu::mov_ss() {
	BOOL found = FALSE;

	_asm
	{
		push ss;
		pop ss;
		pushfd;
		test byte ptr[esp + 1], 1;
		jne fnd;
		jmp end;
	fnd:
		mov found, 1;
	end:
		nop;
	}

	if (found) { return security::internal::debug_results::mov_ss; }
}

int security::check_security(const char* pid) {

	return (security::internal::memory::being_debugged_peb() != 0 || security::internal::memory::remote_debugger_present() != 0 || security::internal::memory::check_window_name() != 0
		|| security::internal::memory::is_debugger_present() != 0 || security::internal::memory::nt_global_flag_peb() != 0 || security::internal::memory::nt_query_information_process() != 0
		|| security::internal::memory::nt_set_information_thread() != 0 || security::internal::memory::debug_active_process(pid) != 0
		|| security::internal::exceptions::close_handle_exception() != 0 || security::internal::exceptions::single_step_exception() != 0 || security::internal::exceptions::int_3() != 0
		|| security::internal::exceptions::int_2d() != 0 || security::internal::exceptions::prefix_hop() != 0
		|| security::internal::timing::rdtsc() != 0 || security::internal::timing::query_performance_counter() != 0 || security::internal::timing::get_tick_count() != 0
		|| security::internal::cpu::hardware_debug_registers() != 0 || security::internal::cpu::mov_ss() != 0);
}
