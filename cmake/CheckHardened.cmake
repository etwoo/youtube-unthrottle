include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)

macro(my_msg str)
	message(STATUS "Detecting -fhardened" ${str})
endmacro()

macro(check_hardened lib)
	my_msg("")

	cmake_push_check_state()
	set(CMAKE_REQUIRED_QUIET ON)
	set(CMAKE_REQUIRED_FLAGS -O2) # req'ed by _FORTIFY_SOURCE
	check_c_compiler_flag(-fhardened CFLAG_HARDENED)
	cmake_pop_check_state()

	if (CFLAG_HARDENED)
		my_msg(" - Success")
		target_compile_options(${lib} INTERFACE -fhardened)
	else (CFLAG_HARDENED)
		my_msg(" - Failed")
		# -fhardened unsupported; set constituent options individually
		target_compile_options(${lib} INTERFACE
			-D_FORTIFY_SOURCE=3
			-D_GLIBCXX_ASSERTIONS
			-fPIE -pie
			-Wl,-z,now
			-Wl,-z,relro
			-fstack-protector-strong
			-fstack-clash-protection
			-fcf-protection=full
		)
	endif (CFLAG_HARDENED)

	target_compile_options(${lib} INTERFACE -O2) # req'ed by _FORTIFY_SOURCE
endmacro()
