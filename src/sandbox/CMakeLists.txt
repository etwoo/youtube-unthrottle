if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	add_subdirectory(linux)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	add_subdirectory(darwin)
endif ()

target_sources(youtube PRIVATE
	verify.c
)
