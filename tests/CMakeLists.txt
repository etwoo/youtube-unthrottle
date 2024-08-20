include(CTest)

macro(add_greatest source)
	set(test_exe greatest-${source})
	add_test(${source} ${test_exe} -v)
	add_executable(${test_exe})
	target_sources(${test_exe} PRIVATE ${source}.c)
	target_include_directories(${test_exe} PRIVATE
		${PROJECT_SOURCE_DIR}/src
		${greatest_SOURCE_DIR}
	)
	target_link_libraries(${test_exe} PRIVATE youtube my_cflags)
endmacro()

add_subdirectory(cli)
add_subdirectory(fuzzer)
add_subdirectory(js)
add_subdirectory(re)
add_subdirectory(sandbox)
add_subdirectory(youtube)
