target_include_directories(youtube PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(youtube PRIVATE my_cflags)

add_subdirectory(lib)
add_subdirectory(protocol)
add_subdirectory(sandbox)
add_subdirectory(sys)

target_sources(youtube PRIVATE
	result.c
	sandbox.c
	youtube.c
)

option(WITH_DEBUG_LOG "Enable runtime debug logging" OFF)
if (WITH_DEBUG_LOG)
	target_compile_definitions(youtube PRIVATE WITH_DEBUG_LOG)
endif (WITH_DEBUG_LOG)

option(WITH_CURL_VERBOSE "Enable verbose libcurl logging" OFF)
if (WITH_CURL_VERBOSE)
	target_compile_definitions(youtube PRIVATE WITH_CURL_VERBOSE)
endif (WITH_CURL_VERBOSE)
