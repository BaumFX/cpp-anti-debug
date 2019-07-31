#pragma once

#include <Windows.h>
#include <Winternl.h>

#pragma warning( disable : 4091)

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);

//main namespace for security
namespace security {
	//internal (used by the security itself, no need to be used outside of namespace)
	namespace internal {
		//dynamically resolved functions
		typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_  unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);
		typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);

		//enum for the results of the antidebugger
		extern enum debug_results
		{
			//nothing was caught, value = 0
			none, //0

			//something caught in memory (1 - 9)
			being_debugged_peb, //1
			remote_debugger_present, //2
			debugger_is_present, //3
			dbg_global_flag, //4
			nt_query_information_process, //5
			find_window, //6
			output_debug_string, //7
			nt_set_information_thread, //8
			debug_active_process, //9

			//something caught in exceptions (10 - 14)
			close_handle_exception, //10
			single_step, //11
			int_3_cc, //12
			int_2, //13
			prefix_hop, //14

			//something caught with timings (15 - 17)
			rdtsc, //15
			query_performance_counter, //16
			get_tick_count, //17

			//something caught in cpu (18 - 19)
			hardware_debug_registers, //18
			mov_ss, //19
		};

		namespace memory {
			int being_debugged_peb();
			int remote_debugger_present();
			int check_window_name();
			int is_debugger_present();
			int nt_global_flag_peb();
			int nt_query_information_process();
			int nt_set_information_thread();
			int debug_active_process(const char*);
		}

		namespace exceptions {
			int close_handle_exception();
			int single_step_exception();
			int int_3();
			int int_2d();
			int prefix_hop();
		}

		namespace timing {
			int rdtsc();
			int query_performance_counter();
			int get_tick_count();
		}

		namespace cpu {
			int hardware_debug_registers();
			int mov_ss();
		}
	}

	int check_security(const char*);
}
