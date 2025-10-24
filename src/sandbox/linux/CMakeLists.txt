target_sources(youtube PRIVATE
	landlock.c
	seccomp.c
)

include(TargetLinkPkgConfig)
target_link_from_pkg_config(youtube libseccomp)
