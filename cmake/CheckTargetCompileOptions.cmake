include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)

macro(my_msg compiler_option str)
	message(STATUS "Detecting " ${compiler_option} ${str})
endmacro()

macro(check_target_compile_options lib compiler_option)
	my_msg(${compiler_option} "")
	unset(CHECK_CFLAG CACHE) # handle any pollution from past invocations

	cmake_push_check_state()
	set(CMAKE_REQUIRED_QUIET ON)
	check_c_compiler_flag(${compiler_option} CHECK_CFLAG)
	cmake_pop_check_state()

	if (CHECK_CFLAG)
		my_msg(${compiler_option} " - Success")
		target_compile_options(${lib} INTERFACE ${compiler_option})
	else (CHECK_CFLAG)
		my_msg(${compiler_option} " - Failed")
	endif (CHECK_CFLAG)

	unset(CHECK_CFLAG CACHE) # cleanup for potential future invocations
endmacro()
