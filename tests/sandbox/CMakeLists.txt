CPMAddPackage(
	NAME greatest
	GIT_REPOSITORY https://github.com/silentbicycle/greatest
	VERSION 1.5.0
	DOWNLOAD_ONLY YES
)

if (NOT greatest_ADDED)
	message(STATUS "Could not add greatest.h unit test dependency")
endif (NOT greatest_ADDED)

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
