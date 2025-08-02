target_sources(youtube PRIVATE
	landlock.c
	seccomp.c
)

pkg_check_modules(SECCOMP REQUIRED libseccomp)

target_include_directories(youtube SYSTEM PRIVATE
	${SECCOMP_INCLUDE_DIRS}
)
target_link_directories(youtube PUBLIC
	${SECCOMP_LIBRARY_DIRS}
)
target_link_libraries(youtube PRIVATE
	${SECCOMP_LIBRARIES}
)
