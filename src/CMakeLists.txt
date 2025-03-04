add_library(youtube)

target_include_directories(youtube PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_include_directories(youtube PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(youtube PRIVATE my_cflags)

add_subdirectory(lib)
add_subdirectory(sandbox)
add_subdirectory(sys)

target_sources(youtube PRIVATE
	result.c
	sandbox.c
	youtube.c
)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
	message(STATUS "Enabling runtime debug output")
	target_compile_definitions(youtube PRIVATE WITH_DEBUG_OUTPUT)
endif (CMAKE_BUILD_TYPE STREQUAL Debug)
