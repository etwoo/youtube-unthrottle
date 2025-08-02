target_sources(youtube PRIVATE
	landlock.c
	seccomp.c
)

target_link_libraries(youtube PRIVATE
	seccomp
)
