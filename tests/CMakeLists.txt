include(CTest)
add_test(NAME cli-help COMMAND youtube-unthrottle --help)
add_test(NAME cli-try-sandbox COMMAND youtube-unthrottle --try-sandbox)

if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
	add_subdirectory(fuzzer)
endif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
