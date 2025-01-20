include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)

macro(my_msg compiler_option str)
	message(STATUS "Detecting " ${compiler_option} ${str})
endmacro()

macro(check_sanitizer lib compiler_option link_library check_var)
	my_msg(${compiler_option} "")

	cmake_push_check_state()
	set(CMAKE_REQUIRED_QUIET ON)
	set(CMAKE_REQUIRED_LIBRARIES ${link_library})
	check_c_compiler_flag(${compiler_option} ${check_var})
	cmake_pop_check_state()

	if (${check_var})
		my_msg(${compiler_option} " - Success")
		target_compile_options(${lib} INTERFACE ${compiler_option})
		target_link_libraries(${lib} INTERFACE ${link_library})
	else (${check_var})
		my_msg(${compiler_option} " - Failed")
	endif (${check_var})
endmacro()
