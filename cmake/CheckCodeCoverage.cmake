include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)

macro(my_msg str)
	message(STATUS "Detecting code coverage support" ${str})
endmacro()

macro(check_code_coverage lib)
	my_msg("")
	cmake_push_check_state()

	set(CMAKE_REQUIRED_QUIET ON)
	check_c_compiler_flag(-fprofile-instr-generate CFLAG_PROFILE_INSTR_GEN)
	if (NOT CFLAG_PROFILE_INSTR_GEN)
		my_msg(" - Failed")
		message(FATAL_ERROR "No support for -fprofile-instr-generate")
	endif (NOT CFLAG_PROFILE_INSTR_GEN)

	set(CMAKE_REQUIRED_FLAGS -fprofile-instr-generate)
	check_c_compiler_flag(-fcoverage-mapping CFLAG_COVERAGE_MAPPING)
	if (NOT CFLAG_COVERAGE_MAPPING)
		my_msg(" - Failed")
		message(FATAL_ERROR "No support for -fcoverage-mapping")
	endif (NOT CFLAG_COVERAGE_MAPPING)

	cmake_pop_check_state()
	my_msg(" - Success")

	target_compile_definitions(${lib} INTERFACE WITH_COVERAGE)

	target_compile_options(${lib} INTERFACE
		-fprofile-instr-generate -fcoverage-mapping
	)
	target_link_options(${lib} INTERFACE
		-fprofile-instr-generate -fcoverage-mapping
	)
endmacro()
