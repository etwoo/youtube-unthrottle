if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
	add_greatest(landlock)
	add_greatest(seccomp)
endif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
