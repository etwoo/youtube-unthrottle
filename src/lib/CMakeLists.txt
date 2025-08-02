target_sources(youtube PRIVATE
	js.c
	re.c
	url.c
)

pkg_check_modules(ADA REQUIRED ada)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(DUKTAPE REQUIRED duktape)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(PCRE2 REQUIRED libpcre2-8)

target_include_directories(youtube SYSTEM PRIVATE
	${ADA_INCLUDE_DIRS}
	${CURL_INCLUDE_DIRS}
	${DUKTAPE_INCLUDE_DIRS}
	${JANSSON_INCLUDE_DIRS}
	${PCRE2_INCLUDE_DIRS}
)
target_link_directories(youtube PUBLIC
	${ADA_LIBRARY_DIRS}
	${CURL_LIBRARY_DIRS}
	${DUKTAPE_LIBRARY_DIRS}
	${JANSSON_LIBRARY_DIRS}
	${PCRE2_LIBRARY_DIRS}
)
target_link_libraries(youtube PRIVATE
	${ADA_LIBRARIES}
	${CURL_LIBRARIES}
	${DUKTAPE_LIBRARIES}
	${JANSSON_LIBRARIES}
	${PCRE2_LIBRARIES}
)
