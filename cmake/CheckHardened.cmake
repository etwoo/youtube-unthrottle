include_guard(GLOBAL)

include(CMakePushCheckState)
include(CheckCCompilerFlag)
include(CheckTargetCompileOptions)

macro(_my_msg_hardened str)
	message(STATUS "Detecting -fhardened" ${str})
endmacro()

macro(check_hardened lib)
	_my_msg_hardened("")

	cmake_push_check_state()
	set(CMAKE_REQUIRED_QUIET ON)
	set(CMAKE_REQUIRED_FLAGS
		"-O2 -Werror"
		#     ^^^^^^ treat all warnings as errors
		# ^^ _FORTIFY_SOURCE requires optimization
	)
	check_c_compiler_flag(-fhardened CFLAG_HARDENED)
	cmake_pop_check_state()

	if (CFLAG_HARDENED)
		_my_msg_hardened(" - Success")
		target_compile_options(${lib} INTERFACE -fhardened)
	else (CFLAG_HARDENED)
		_my_msg_hardened(" - Failed")
		# -fhardened unsupported; set constituent options individually
		target_compile_options(${lib} INTERFACE
			-D_FORTIFY_SOURCE=3
			-D_GLIBCXX_ASSERTIONS
			-fPIE -pie
			-Wl,-z,now
			-Wl,-z,relro
			-fstack-protector-strong
			-fstack-clash-protection
		)
		# enable amd64-only option conditionally (disable under arm64)
		check_target_compile_options(${lib} -fcf-protection=full)
	endif (CFLAG_HARDENED)

	#
	# enable arm64-only hardening option conditionally
	#
	# note: remove this if -fhardened ever includes -mbranch-protection
	#
	check_target_compile_options(${lib} -mbranch-protection=standard)

	target_compile_options(${lib} INTERFACE -O2) # for _FORTIFY_SOURCE
endmacro()
