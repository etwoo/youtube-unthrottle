target_sources(youtube PRIVATE
	debug.c
	tmpfile.c
	write.c
)

target_link_libraries(youtube PRIVATE
	ada
	curl
	duktape
	jansson
	pcre2-8
)
