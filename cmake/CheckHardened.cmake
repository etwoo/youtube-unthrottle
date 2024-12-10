include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)

macro(check_hardened check_var compiler_option dependencies)
	cmake_push_check_state()
	set(CMAKE_REQUIRED_FLAGS ${dependencies})
	check_c_compiler_flag(${compiler_option} ${check_var})
	cmake_pop_check_state()
endmacro()
