include(CTest)

add_subdirectory(cli)
add_subdirectory(fuzzer)

set(TEST_SOURCES "")

macro(register_test source)
	list(APPEND TEST_SOURCES ${source}.c)
	set(TEST_SOURCES "${TEST_SOURCES}" PARENT_SCOPE)
	add_test(${source} test_driver ${source} -v)
endmacro()

macro(generate_test_driver)
	create_test_sourcelist(generated_sources test_driver.c
		${TEST_SOURCES}
		EXTRA_INCLUDE test_driver.h
	)
	add_executable(test_driver ${generated_sources})
	target_include_directories(test_driver PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR} # for test_driver.h
		${PROJECT_SOURCE_DIR}/src   # for debug.h, tmpfile.h, etc
		${greatest_SOURCE_DIR}      # for greatest.h
	)
	target_link_libraries(test_driver PRIVATE sanitizers youtube my_cflags)
endmacro()

register_test(js)
register_test(landlock)
register_test(re)
register_test(result)
register_test(seccomp) # TODO: set envvar to disable lsan for seccomp test
register_test(youtube)

generate_test_driver()
