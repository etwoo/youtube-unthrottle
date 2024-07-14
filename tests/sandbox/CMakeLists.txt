CPMAddPackage(
	NAME greatest
	GIT_REPOSITORY https://github.com/silentbicycle/greatest
	VERSION 1.5.0
	DOWNLOAD_ONLY YES
)

add_test(sandbox sandbox -v)
add_executable(sandbox)
target_sources(sandbox PRIVATE sandbox.c)
target_include_directories(sandbox PRIVATE
	${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(sandbox PRIVATE youtube)

if (greatest_ADDED)
	target_include_directories(sandbox SYSTEM PRIVATE
		${greatest_SOURCE_DIR}
	)
endif (greatest_ADDED)
