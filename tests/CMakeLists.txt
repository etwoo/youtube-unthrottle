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
	create_test_sourcelist(generated_sources
		test_driver.c
		${TEST_SOURCES}
		EXTRA_INCLUDE test_driver.h
	)
	add_executable(test-driver
		${generated_sources}
	)
	target_include_directories(test-driver PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR} # for test_driver.h
		${PROJECT_SOURCE_DIR}/src   # for debug.h, tmpfile.h, etc
		${greatest_SOURCE_DIR}      # for greatest.h
	)
	target_link_libraries(test-driver PRIVATE my_cflags sanitizers youtube)
endmacro()

register_test(js)
register_test(landlock)
register_test(re)
register_test(result)
register_test(seccomp "ASAN_OPTIONS=detect_leaks=0")
register_test(youtube)

generate_test_driver()
