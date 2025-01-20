add_library(youtube)
target_sources(youtube PRIVATE
	debug.c
	js.c
	re.c
	result.c
	sandbox.c
	tmpfile.c
	url.c
	write.c
	youtube.c
)
target_include_directories(youtube PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(youtube PRIVATE my_cflags)
target_link_libraries(youtube PRIVATE
	ada
	curl
	duktape
	jansson
	pcre2-8
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	target_sources(youtube PRIVATE
		landlock.c
		seccomp.c
	)
	target_link_libraries(youtube PRIVATE
		seccomp
	)
endif (CMAKE_SYSTEM_NAME STREQUAL "Linux")

if (CMAKE_BUILD_TYPE STREQUAL Debug)
	message(STATUS "Enabling runtime debug output")
	target_compile_definitions(youtube PRIVATE WITH_DEBUG_OUTPUT)
endif (CMAKE_BUILD_TYPE STREQUAL Debug)
