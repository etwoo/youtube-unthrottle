target_sources(youtube PRIVATE
	debug.c
	state.c
	stream.c
	varint.c
)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
	target_link_libraries(youtube-protocol PRIVATE
		resolv # for b64_pton()
	)
endif (NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
