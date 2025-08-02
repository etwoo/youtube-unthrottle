include_guard(GLOBAL)

find_package(PkgConfig REQUIRED)

function(target_link_from_pkg_config target pkg)
	pkg_check_modules(${pkg} REQUIRED IMPORTED_TARGET GLOBAL ${pkg})
	target_link_libraries(${target} PRIVATE "PkgConfig::${pkg}")
endfunction()
