add_subdirectory(cli)

if (BUILD_FUZZER)
	add_subdirectory(fuzzer)
endif (BUILD_FUZZER)

set(TEST_SOURCES "")

macro(register_test source)
	set(envvars ${ARGN}) # optional second argument specifies envvars

	list(APPEND TEST_SOURCES ${source}.c)
	set(TEST_SOURCES "${TEST_SOURCES}" PARENT_SCOPE)

	set(cmd "${CMAKE_CURRENT_BINARY_DIR}/test-driver" ${source} -v)
	if (envvars)
		add_test(${source} /usr/bin/env ${envvars} ${cmd})
	else (envvars)
		add_test(${source} ${cmd})
	endif (envvars)
endmacro()

macro(generate_test_driver)
	add_custom_command(
		OUTPUT test_suites.c
		COMMAND
			${PROJECT_SOURCE_DIR}/scripts/collect-test-suites.sh
			${CMAKE_CURRENT_BINARY_DIR}/test_suites.c
			${TEST_SOURCES}
		DEPENDS
			${PROJECT_SOURCE_DIR}/scripts/collect-test-suites.sh
			${TEST_SOURCES}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)
	create_test_sourcelist(generated_sources
		test_driver.c
		${TEST_SOURCES}
	)
	set_source_files_properties(test_driver.c PROPERTIES SKIP_LINTING ON)
	add_executable(test-driver
		${generated_sources}
		test_suites.c
		test_network.c
		coverage.c
	)
	target_include_directories(test-driver PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR} # for coverage.h, test_macros.h, etc
		${PROJECT_SOURCE_DIR}/src   # for debug.h, tmpfile.h, etc
	)
	target_include_directories(test-driver SYSTEM PRIVATE
		${greatest_SOURCE_DIR}      # for greatest.h
	)
	target_link_libraries(test-driver PRIVATE
		my_cflags
		sanitizers
		youtube
		youtube-protobuf # depend on this target for its PUBLIC includes
	)
endmacro()

register_test(js)
register_test(protocol)
register_test(re)
register_test(result)
register_test(sandbox "ASAN_OPTIONS=detect_leaks=0")
register_test(write_wrapper)
register_test(youtube)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	register_test(landlock)
	register_test(seccomp "ASAN_OPTIONS=detect_leaks=0")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	register_test(seatbelt)
endif ()

generate_test_driver()

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND CMAKE_C_COMPILER_ID STREQUAL "GNU")
	# suppress warnings in generated code
	set_source_files_properties(test_driver.c PROPERTIES COMPILE_OPTIONS
		"-Wno-analyzer-null-argument;-Wno-analyzer-use-of-uninitialized-value"
	)
endif ()
