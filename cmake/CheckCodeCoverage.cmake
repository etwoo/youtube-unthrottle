include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)

function(check_code_coverage flags)
	check_c_compiler_flag(-fprofile-instr-generate CFLAG_PROFILE_INSTR_GEN)

	if (NOT CFLAG_PROFILE_INSTR_GEN)
		message(FATAL_ERROR "No support for -fprofile-instr-generate")
	endif (NOT CFLAG_PROFILE_INSTR_GEN)

	cmake_push_check_state()
	set(CMAKE_REQUIRED_FLAGS -fprofile-instr-generate)
	check_c_compiler_flag(-fcoverage-mapping CFLAG_COVERAGE_MAPPING)
	cmake_pop_check_state()

	if (NOT CFLAG_COVERAGE_MAPPING)
		message(FATAL_ERROR "No support for -fcoverage-mapping")
	endif (NOT CFLAG_COVERAGE_MAPPING)

	set(${flags} "-fprofile-instr-generate;-fcoverage-mapping" PARENT_SCOPE)
endfunction()
