include(CTest)
add_test(NAME cli-help COMMAND youtube-unthrottle --help)
add_test(NAME cli-try-sandbox COMMAND youtube-unthrottle --try-sandbox)

add_subdirectory(fuzzer)
add_subdirectory(sandbox)
