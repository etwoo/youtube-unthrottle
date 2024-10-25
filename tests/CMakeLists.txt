include(CTest)

add_subdirectory(cli)
add_subdirectory(fuzzer)

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
			${CMAKE_SOURCE_DIR}/scripts/collect-test-suites.sh
			${CMAKE_CURRENT_BINARY_DIR}/test_suites.c
			${TEST_SOURCES}
		DEPENDS
			${CMAKE_SOURCE_DIR}/scripts/collect-test-suites.sh
			${TEST_SOURCES}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)
	create_test_sourcelist(generated_sources
		test_driver.c
		${TEST_SOURCES}
	)
	add_executable(test-driver
		${generated_sources}
		test_suites.c
		coverage.c
	)
	target_include_directories(test-driver PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR} # for test_driver.h
		${PROJECT_SOURCE_DIR}/src   # for debug.h, tmpfile.h, etc
		${greatest_SOURCE_DIR}      # for greatest.h
	)
	target_link_libraries(test-driver PRIVATE my_cflags sanitizers youtube)
endmacro()

register_test(js)
register_test(re)
register_test(result)
register_test(sandbox "ASAN_OPTIONS=detect_leaks=0")
register_test(youtube)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	register_test(landlock)
	register_test(seccomp "ASAN_OPTIONS=detect_leaks=0")
endif (CMAKE_SYSTEM_NAME STREQUAL "Linux")

generate_test_driver()
