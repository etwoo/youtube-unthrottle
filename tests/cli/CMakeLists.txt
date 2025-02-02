add_test(NAME cli-help COMMAND youtube-unthrottle --help)
add_test(NAME cli-try-sandbox COMMAND youtube-unthrottle --try-sandbox)
add_test(NAME cli-errors COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/cli-errors.sh
	${CMAKE_BINARY_DIR}/youtube-unthrottle
)
