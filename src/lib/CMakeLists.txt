target_sources(youtube PRIVATE
	js.c
	re.c
	url.c
)

target_link_libraries(youtube PRIVATE
	ada
	curl
	duktape
	jansson
	pcre2-8
)
