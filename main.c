/*
 * Extract video and audio stream URLs from a YouTube link passed via argv[1],
 * and then print the results to stdout, for subsequent use by mpv.
 *
 * The main challenge here is that the stream URLs contain parameters
 * that must be deobfuscated using JavaScript fragments supplied elsewhere
 * in the YouTube payload. This is why solving this puzzle requires the use
 * of an embedded JavaScript engine (in this case, Duktape).
 */

#include "youtube.h"

#include <stdio.h>
#include <string.h>
#include <sysexits.h>

static const char ARG_HELP[] = "--help";

static int
usage(const char *cmd, int rc)
{
	fprintf(stderr, "Usage: %s [URL]\n", cmd);
	return rc;
}

int
main(int argc, const char *argv[])
{
	if (argc < 2) {
		return usage(argv[0], EX_USAGE);
	}

	if (0 == strncmp(ARG_HELP, argv[1], strlen(ARG_HELP))) {
		return usage(argv[0], EX_OK);
	}

	youtube_global_init();
	youtube_handle_t stream = youtube_stream_init();

	bool should_print = youtube_stream_setup(stream, argv[1]);
	if (should_print) {
		youtube_stream_print(stream);
	}

	youtube_stream_cleanup(stream);
	youtube_global_cleanup();
	return should_print ? EX_OK : EX_DATAERR;
}

/* TODO: drop privileges via pledge(), chroot, namespaces, or equivalent */
