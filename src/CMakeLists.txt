add_library(youtube ${CMAKE_CURRENT_BINARY_DIR})
target_sources(youtube PRIVATE
	debug.c
	js.c
	landlock.c
	re.c
	sandbox.c
	tmpfile.c
	url.c
	youtube.c
)
target_include_directories(youtube PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(youtube PUBLIC my_cflags)

# choose between libyoutube.a (release build) and libyoutubed.a (debug build)
set_target_properties(youtube PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})
set_target_properties(youtube PROPERTIES
	POSITION_INDEPENDENT_CODE ${BUILD_SHARED_LIBS}
)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
	message(STATUS "Enabling runtime debug output")
	target_compile_definitions(youtube PRIVATE WITH_DEBUG_OUTPUT)
endif()
