include_guard(GLOBAL)

macro(adjust_global_includes_and_libraries)
	if (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
		message(STATUS "Using libraries installed via OpenBSD ports")
		include_directories(SYSTEM /usr/local/include)
		link_directories(/usr/local/lib)
	else (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
		find_program(BREW_COMMAND brew)
		if (BREW_COMMAND)
			execute_process(
				COMMAND ${BREW_COMMAND} --prefix
				OUTPUT_VARIABLE BREW_DIR
				OUTPUT_STRIP_TRAILING_WHITESPACE
			)
			message(STATUS "Using Homebrew packages: ${BREW_DIR}")
			include_directories(SYSTEM ${BREW_DIR}/include)
			link_directories(${BREW_DIR}/lib)
		endif (BREW_COMMAND)
	endif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
endmacro()
