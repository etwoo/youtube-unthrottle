include_guard(GLOBAL)

find_package(PkgConfig)

function(target_link_from_pkg_config target pkg)
	pkg_check_modules(MYPKG REQUIRED IMPORTED_TARGET ${pkg})
	target_include_directories(${target} PRIVATE ${MYPKG_INCLUDE_DIRS})
	target_link_libraries(${target} PRIVATE ${MYPKG_LINK_LIBRARIES})
endfunction()
