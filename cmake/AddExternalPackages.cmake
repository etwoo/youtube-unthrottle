include_guard(GLOBAL)

include(get_cpm)

macro(add_external_packages)
	# Note: defines ${googlevideo_SOURCE_DIR}, ${googlevideo_BINARY_DIR}
	CPMAddPackage(
		NAME googlevideo
		GITHUB_REPOSITORY LuanRT/googlevideo
		GIT_TAG e185cbcd88a13e2c45a5668ffa6c860bf302efee # 4.0.1
		DOWNLOAD_ONLY YES
	)
	if (BUILD_TESTING)
		# Note: defines ${greatest_SOURCE_DIR}
		CPMAddPackage(
			NAME greatest
			GITHUB_REPOSITORY silentbicycle/greatest
			VERSION 1.5.0
			DOWNLOAD_ONLY YES
		)
	endif (BUILD_TESTING)
	if (BUILD_COVERAGE)
		CPMAddPackage(
			NAME lcov-to-cobertura-xml
			GITHUB_REPOSITORY eriwen/lcov-to-cobertura-xml
			GIT_TAG 028da3798355d0260c6c6491b39347d84ca7a02d
			DOWNLOAD_ONLY YES
		)
	endif (BUILD_COVERAGE)
endmacro()
