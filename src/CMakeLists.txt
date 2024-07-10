add_library(youtube ${CMAKE_CURRENT_BINARY_DIR})
target_sources(youtube PRIVATE
	debug.c
	js.c
	re.c
	sandbox.c
	tmpfile.c
	url.c
	youtube.c
)
target_include_directories(youtube PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(youtube PRIVATE my_cflags)

add_library(libcurl SHARED IMPORTED)
add_library(libduktape SHARED IMPORTED)
add_library(libpcre2-8 SHARED IMPORTED)
target_link_libraries(youtube PRIVATE
	curl
	duktape
	pcre2-8
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	target_sources(youtube PRIVATE
		landlock.c
		seccomp.c
	)
	add_library(libseccomp SHARED IMPORTED)
	target_link_libraries(youtube PRIVATE
		seccomp
	)
endif (CMAKE_SYSTEM_NAME STREQUAL "Linux")

# choose between libyoutube.a (release build) and libyoutubed.a (debug build)
set_target_properties(youtube PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})
set_target_properties(youtube PROPERTIES
	POSITION_INDEPENDENT_CODE ${BUILD_SHARED_LIBS}
)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
	message(STATUS "Enabling runtime debug output")
	target_compile_definitions(youtube PRIVATE WITH_DEBUG_OUTPUT)
endif()
