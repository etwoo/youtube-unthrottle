target_sources(youtube PRIVATE
	js.c
	re.c
	url.c
)

include(TargetLinkPkgConfig)
target_link_from_pkg_config(youtube ada)
target_link_from_pkg_config(youtube libcurl)
target_link_from_pkg_config(youtube jansson)
target_link_from_pkg_config(youtube libpcre2-8)
target_link_from_pkg_config(youtube quickjs)
target_link_libraries(youtube PRIVATE m) # quickjs implicitly depends on libm
