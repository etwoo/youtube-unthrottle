macro(add_sandbox_test source)
	set(target sandbox-${source})
	add_test(${target} ${target} -v)
	add_executable(${target})
	target_sources(${target} PRIVATE ${source}.c)
	target_include_directories(${target} PRIVATE
		${PROJECT_SOURCE_DIR}/src
		${greatest_SOURCE_DIR}
	)
	target_link_libraries(${target} PRIVATE youtube my_cflags)
endmacro()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	add_sandbox_test(landlock)
	add_sandbox_test(seccomp)
endif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
