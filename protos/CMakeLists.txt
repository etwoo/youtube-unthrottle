CPMAddPackage(
	NAME innertube
	GITHUB_REPOSITORY davidzeng0/innertube
	GIT_TAG 75781439c4b4de5b10dbae4fb6645a17c85c1d0c
	DOWNLOAD_ONLY YES
	PATCHES innertube.patch
)

add_custom_command(
	OUTPUT
		google/protobuf/any.pb-c.c
		video/storage/format_description.pb-c.c
		video_streaming/client_abr_state.pb-c.c
		video_streaming/media_capabilities.pb-c.c
		video_streaming/per_playback_attributes.pb-c.c
		video_streaming/streamer_context.pb-c.c
		video_streaming/video_playback_request_proto.pb-c.c
		youtube/api/innertube/audio_quality.pb-c.c
		youtube/api/innertube/client_info.pb-c.c
		youtube/api/innertube/detailed_network_type.pb-c.c
		youtube/api/innertube/drm_track_type.pb-c.c
		youtube/api/innertube/mobile_data_plan_info.pb-c.c
		youtube/api/innertube/network_metered_state.pb-c.c
		youtube/api/innertube/playback_audio_route_output_type.pb-c.c
		youtube/api/innertube/player_type.pb-c.c
		youtube/api/innertube/user_interface_theme.pb-c.c
		youtube/api/innertube/video_quality_setting.pb-c.c
	COMMAND protoc
		--proto_path=${innertube_SOURCE_DIR}/protos
		--c_out=${CMAKE_CURRENT_BINARY_DIR}
		google/protobuf/any.proto
		video/storage/format_description.proto
		video_streaming/client_abr_state.proto
		video_streaming/media_capabilities.proto
		video_streaming/per_playback_attributes.proto
		video_streaming/streamer_context.proto
		video_streaming/video_playback_request_proto.proto
		youtube/api/innertube/audio_quality.proto
		youtube/api/innertube/client_info.proto
		youtube/api/innertube/detailed_network_type.proto
		youtube/api/innertube/drm_track_type.proto
		youtube/api/innertube/mobile_data_plan_info.proto
		youtube/api/innertube/network_metered_state.proto
		youtube/api/innertube/playback_audio_route_output_type.proto
		youtube/api/innertube/player_type.proto
		youtube/api/innertube/user_interface_theme.proto
		youtube/api/innertube/video_quality_setting.proto
)

add_library(youtube-protobufs)
target_sources(youtube-protobufs PRIVATE
	google/protobuf/any.pb-c.c
	video/storage/format_description.pb-c.c
	video_streaming/client_abr_state.pb-c.c
	video_streaming/media_capabilities.pb-c.c
	video_streaming/per_playback_attributes.pb-c.c
	video_streaming/streamer_context.pb-c.c
	video_streaming/video_playback_request_proto.pb-c.c
	youtube/api/innertube/audio_quality.pb-c.c
	youtube/api/innertube/client_info.pb-c.c
	youtube/api/innertube/detailed_network_type.pb-c.c
	youtube/api/innertube/drm_track_type.pb-c.c
	youtube/api/innertube/mobile_data_plan_info.pb-c.c
	youtube/api/innertube/network_metered_state.pb-c.c
	youtube/api/innertube/playback_audio_route_output_type.pb-c.c
	youtube/api/innertube/player_type.pb-c.c
	youtube/api/innertube/user_interface_theme.pb-c.c
	youtube/api/innertube/video_quality_setting.pb-c.c
)
target_include_directories(youtube-protobufs PUBLIC
	${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(youtube-protobufs PRIVATE
	protobuf-c
)
