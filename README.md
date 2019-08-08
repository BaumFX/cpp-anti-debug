# cpp-anti-debug

a c++ library that offers debugger detection.

## getting started

these instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

literally download & include

you can then use

```
#include anti_debug.hpp

//will contain 0 if no debuggers etc. were found, returns -1 if something was found, you could edit the check_security() function
//to return the specific error code
//see anti_debug.hpp for more information
int security_status = security::check_security();

if(security_status != 0) {
  std::cout << "security check was not successful." << std::endl;
}
```

## features
string encryption to prevent static anlysis, strings get returned from one central function (if possible)
the library features the following functions (in-depth explanation for most of them is in the code):
alternatively you can use the big function check_security() to run all checks.
```
		namespace memory {
			int being_debugged_peb();
			int remote_debugger_present();
			int check_window_name();
			int is_debugger_present();
			int nt_global_flag_peb();
			int nt_query_information_process();
			int nt_set_information_thread();
			int debug_active_process(const char*);
			int write_buffer();
		}

		namespace exceptions {
			int close_handle_exception();
			int single_step_exception();
			int int_3();
			int int_2d();
			int prefix_hop();
			int debug_string();
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
```

## todo:
add virtualization and sandboxing checks to prevent your files from being executed in virtualized environments or sandboxes

add detections for dumping tools

## notes:
it's recommended to run the check multiple times (once every X seconds etc.)

you will need to come up with the "xor_cc.hpp" yourself, it's a generic precompiler instruction that replaces xor("string") with a call to a generic xor function and passes the result of the first call to it (strings get unencrypted at runtime). you should be able to figure this out yourself.

## contributing
please create a pull request if you have made another check and want to include it or create an issue if you want me to add another check.

## versioning

no versions but updates (sometimes)

## authors
* **John 'cetfor' Toterhi** - *initial work on the stuffs* - [GitHub](https://github.com/cetfor)
* **Robert 'BaumFX'** - *refactored, commented stuff and added stuff* - [website](https://baumfx.xyz) - [GitHub](https://github.com/BaumFX)

## license

its like (insert current line amount) lines but dont say you made it, okay?
