include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)

macro(check_sanitizer check_var compiler_option link_library)
	cmake_push_check_state()
	set(CMAKE_REQUIRED_LIBRARIES ${link_library})
	check_c_compiler_flag(${compiler_option} ${check_var})
	cmake_pop_check_state()
endmacro()
