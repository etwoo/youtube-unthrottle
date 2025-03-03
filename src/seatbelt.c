#include "seatbelt.h"

#include "array.h"
#include "debug.h"
#include "seatbelt_os_api.h"

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>

/*
 * Some helpful Seatbelt (macOS sandbox) references:
 *
 * https://newosxbook.com/files/HITSB.pdf
 * https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf
 * https://media.blackhat.com/bh-dc-11/Blazakis/BlackHat_DC_2011_Blazakis_Apple%20Sandbox-Slides.pdf
 * https://media.blackhat.com/bh-dc-11/Blazakis/BlackHat_DC_2011_Blazakis_Apple_Sandbox-wp.pdf
 * https://bdash.net.nz/posts/sandboxing-on-macos/
 * https://searchfox.org/mozilla-central/source/security/sandbox/mac/SandboxPolicySocket.h
 * https://github.com/chromium/chromium/blob/main/sandbox/mac/README.md
 * https://github.com/chromium/chromium/blob/main/sandbox/mac/seatbelt_sandbox_design.md#sandbox-profile-language
 * https://github.com/chromium/chromium/blob/main/sandbox/policy/mac/network.sb
 * https://github.com/steven-michaud/SandboxMirror/blob/master/app-sandbox.md
 * https://github.com/kristapsdz/oconfigure/blob/master/test-sandbox_init.c
 * https://github.com/opa334/opainject/blob/main/sandbox.h
 */

const unsigned SEATBELT_INET = 0x01;
const unsigned SEATBELT_TMPFILE = 0x02;
const unsigned SEATBELT_RPATH = 0x04;

struct seatbelt_extension {
	unsigned flag;
	char *name;
	unsigned err_issue;
	unsigned err_consume;
	unsigned err_release;
};

static const struct seatbelt_extension SEATBELT_EXTENSIONS[] = {
	{
		SEATBELT_INET,
		"com.apple.security.network.client",
		ERR_SANDBOX_SEATBELT_ISSUE_INET,
		ERR_SANDBOX_SEATBELT_CONSUME_INET,
		ERR_SANDBOX_SEATBELT_RELEASE_INET,
	},
	{
		SEATBELT_TMPFILE,
		"com.apple.app-sandbox.write",
		ERR_SANDBOX_SEATBELT_ISSUE_TMPFILE,
		ERR_SANDBOX_SEATBELT_CONSUME_TMPFILE,
		ERR_SANDBOX_SEATBELT_RELEASE_TMPFILE,
	},
	{
		SEATBELT_RPATH,
		"com.apple.app-sandbox.read",
		ERR_SANDBOX_SEATBELT_ISSUE_RPATH,
		ERR_SANDBOX_SEATBELT_CONSUME_RPATH,
		ERR_SANDBOX_SEATBELT_RELEASE_RPATH,
	},
};

extern const char *SEATBELT_POLICY; /* defined by generated code */

result_t
seatbelt_init(struct seatbelt_context *context)
{
	bool already_done = true;
	for (size_t i = 0; i < ARRAY_SIZE(SEATBELT_EXTENSIONS); ++i) {
		already_done = (context->extensions[i] != 0) && already_done;
	}

	if (already_done) {
		debug("skipping init for already-initialized context");
		return RESULT_OK;
	}

	const char *tmpdir_literal = getenv("TMPDIR");
	if (tmpdir_literal == NULL) {
		return make_result(ERR_SANDBOX_SEATBELT_GETENV_TMPDIR);
	}
	debug("got TMPDIR envvar: %s", tmpdir_literal);

	char tmpdir_realpath[PATH_MAX] = {0};
	if (realpath(tmpdir_literal, tmpdir_realpath) == NULL) {
		return make_result(ERR_SANDBOX_SEATBELT_REALPATH_TMPDIR);
	}
	debug("got TMPDIR realpath: %s", tmpdir_realpath);

	char *tokens[ARRAY_SIZE(SEATBELT_EXTENSIONS)] = {0};
	for (size_t i = 0; i < ARRAY_SIZE(SEATBELT_EXTENSIONS); ++i) {
		const struct seatbelt_extension *e = SEATBELT_EXTENSIONS + i;
		tokens[i] = sandbox_extension_issue_generic(e->name, 0);
		if (tokens[i] == NULL) {
			return make_result(e->err_issue);
		}
		debug("issued extension %s; got token %s", e->name, tokens[i]);
	}

	const char *params[] = {"TMPDIR", tmpdir_realpath, NULL};
	char *ep = NULL;
	if (sandbox_init_with_parameters(SEATBELT_POLICY, 0, params, &ep) < 0) {
		sandbox_free_error(ep);
		return make_result(ERR_SANDBOX_SEATBELT_INIT, errno);
	}

	assert(ARRAY_SIZE(SEATBELT_EXTENSIONS) ==
	       ARRAY_SIZE(context->extensions));
	for (size_t i = 0; i < ARRAY_SIZE(SEATBELT_EXTENSIONS); ++i) {
		context->extensions[i] = sandbox_extension_consume(tokens[i]);
		if (context->extensions[i] < 0) {
			return make_result(SEATBELT_EXTENSIONS[i].err_consume);
		}
		debug("consumed token %s; got handle %lld",
		      tokens[i],
		      context->extensions[i]);
	}

	return RESULT_OK;
}

const int64_t SEATBELT_EXTENSION_HANDLE_RELEASED = -1;

result_t
seatbelt_revoke(struct seatbelt_context *context, unsigned flags)
{
	for (size_t i = 0; i < ARRAY_SIZE(SEATBELT_EXTENSIONS); ++i) {
		const struct seatbelt_extension *e = SEATBELT_EXTENSIONS + i;

		const bool match = (0 != (flags & e->flag));
		const int64_t to_release = context->extensions[i];
		if (!match || to_release <= 0) {
			continue;
		}

		const int r = sandbox_extension_release(to_release);
		if (r < 0) {
			return make_result(e->err_release);
		}

		context->extensions[i] = SEATBELT_EXTENSION_HANDLE_RELEASED;
		debug("released handle %lld for %s", to_release, e->name);
	}

	return RESULT_OK;
}
