#include "js.h"

#include "array.h"
#include "debug.h"
#include "re.h"

#include <assert.h>

/*
 * Some helpful Duktape references:
 *
 *   https://duktape.org/api
 */
#include <duktape.h>

static const char *
peek(duk_context *ctx)
{
	return duk_safe_to_string(ctx, -1);
}

/*
 * Set up boilerplate so that it is possible to provide some error logs when
 * given an invalid JSON payload. For reference, see:
 *
 *   https://github.com/svaarala/duktape/issues/386#issuecomment-417087800
 */
static duk_ret_t
try_decode(duk_context *ctx, void *udata __attribute__((unused)))
{
	duk_json_decode(ctx, -1);
	return 1;
}

static const char MTVIDEO[] = "video/";
static const char MTAUDIO[] = "audio/";

void
parse_json(const char *json,
           size_t json_sz,
           struct parse_ops *ops,
           void *userdata)
{
	// debug("Got JSON blob: %.*s", json_sz, json);
	debug("Got JSON blob of size %zd", json_sz);

	duk_ret_t res = DUK_EXEC_ERROR;

	duk_context *ctx = duk_create_heap_default(); /* may return NULL! */
	if (ctx == NULL) {
		warn("duk_create_heap_default() returned NULL");
		goto cleanup;
	}

	duk_push_lstring(ctx, json, json_sz);
	res = duk_safe_call(ctx, try_decode, NULL, 1, 1);
	if (res != DUK_EXEC_SUCCESS) {
		warn("Error in duk_json_decode(): %s", peek(ctx));
		goto cleanup;
	}

	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1) ||
	    0 == duk_get_prop_literal(ctx, -1, "streamingData")) {
		warn("Cannot get .streamingData");
		goto cleanup;
	}
	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1) ||
	    0 == duk_get_prop_literal(ctx, -1, "adaptiveFormats")) {
		warn("Cannot get .streamingData.adaptiveFormats");
		goto cleanup;
	}
	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1)) {
		warn("Cannot iterate over .streamingData.adaptiveFormats");
		goto cleanup;
	}

	bool got_video = false;
	bool got_audio = false;
	bool warned_about_signature_cipher = false;
	const duk_size_t sz = duk_get_length(ctx, -1);
	for (duk_size_t i = 0; i < sz; ++i) {
		/* get i-th element of adaptiveFormats array */
		duk_get_prop_index(ctx, -1, i);

		if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1)) {
			warn("%zd-th element is not object-coercible", i);
			goto cleanup;
		}

		if (0 == duk_get_prop_literal(ctx, -1, "mimeType") ||
		    DUK_TYPE_STRING != duk_get_type(ctx, -1)) {
			warn("Cannot get .mimeType of %zd-th element", i);
			goto cleanup;
		}

		if (0 == duk_get_prop_literal(ctx, -2, "url") ||
		    DUK_TYPE_STRING != duk_get_type(ctx, -1)) {
			warn("Cannot get .url of %zd-th element", i);
			goto cleanup;
		}

		const char *url = duk_get_string(ctx, -1);
		const char *mimetype = duk_get_string(ctx, -2);
		assert(url != NULL && mimetype != NULL);

		if (0 == strncmp(mimetype, MTVIDEO, strlen(MTVIDEO)) &&
		    false == got_video) {
			ops->got_video(url, strlen(url), userdata);
			got_video = true;
		}
		if (0 == strncmp(mimetype, MTAUDIO, strlen(MTAUDIO)) &&
		    false == got_audio) {
			ops->got_audio(url, strlen(url), userdata);
			got_audio = true;
		}

		/*
		 * Check for streamingCipher attribute, which we do not
		 * currently support. Streams with a "streamingCipher"
		 * attribute instead of a plaintext "url" value require
		 * additional deobfuscation logic, similar to (but distinct
		 * from) n-parameter decoding.
		 * */
		const duk_bool_t get_streaming_cipher =
			duk_get_prop_literal(ctx, -3, "signatureCipher");
		if (get_streaming_cipher && !warned_about_signature_cipher) {
			warn("signatureCipher is unsupported!");
			warned_about_signature_cipher = true;
		}
		duk_pop(ctx); /* for .signatureCipher */

		/* restore stack, to prepare for (i+1)-th element */
		duk_pop_3(ctx);
	}

	duk_pop_2(ctx); /* for .streamingData.adaptiveFormats */

cleanup:
	duk_destroy_heap(ctx); /* handles NULL gracefully */
}

void
find_base_js_url(const char *html,
                 size_t sz,
                 const char **basejs,
                 size_t *basejs_sz)
{
	if (!re_capture("\"(/s/player/[^\"]+/base.js)\"",
	                html,
	                sz,
	                basejs,
	                basejs_sz)) {
		warn("Cannot find base.js URL in HTML document");
	} else {
		debug("Parsed base.js URI: %.*s", (int)*basejs_sz, *basejs);
	}
}

static const char *RE_FUNC_NAME[] = {
	"&&\\(c=([^\\]]+)\\[0\\]\\(c\\)",
	"&&\\(b=([^\\]]+)\\[0\\]\\(b\\)",
};

/*
 * Based on: youtube-dl, yt-dlp, rusty_ytdl
 *
 * find_js_deobfuscator() does the following:
 *
 * 1) find <foo> in base.js like: &&(b=foo[0](b)
 * 2) find <bar> in base.js like: var foo=[bar]
 * 3) find <...> in base.js like: bar=function(a){...}
 *
 * The resulting function body is subsequently used like:
 *
 * 4) eval JavaScript fragment like: function(a){...}([$n_param])
 * 5) use return value from step 4 as decoded n-parameter
 */
void
find_js_deobfuscator(const char *js,
                     size_t js_sz,
                     const char **deobfuscator,
                     size_t *deobfuscator_sz)
{
	*deobfuscator = NULL;
	*deobfuscator_sz = 0;

	char escaped[256];
	const char *name = NULL;
	size_t nsz = 0;
	for (size_t i = 0; i < ARRAY_SIZE(RE_FUNC_NAME); ++i) {
		if (re_capture(RE_FUNC_NAME[i], js, js_sz, &name, &nsz)) {
			break;
		}
		warn("Cannot find '%s' in base.js", RE_FUNC_NAME[i]);
	}
	if (name == NULL || nsz == 0) {
		goto cleanup;
	}
	debug("Got function name 1: %.*s", (int)nsz, name);

	if (!re_pattern_escape(name, nsz, escaped, sizeof(escaped))) {
		goto cleanup;
	}
	debug("Escaped function name 1: %s", escaped);

	if (!re_capturef(js,
	                 js_sz,
	                 &name,
	                 &nsz,
	                 "var %s=\\[([^\\]]+)\\]",
	                 escaped)) {
		warn("Cannot find '%.*s' reference in base.js", (int)nsz, name);
		goto cleanup;
	}
	debug("Got function name 2: %.*s", (int)nsz, name);

	if (!re_pattern_escape(name, nsz, escaped, sizeof(escaped))) {
		goto cleanup;
	}
	debug("Escaped function name 2: %s", escaped);

	if (!re_capturef(js,
	                 js_sz,
	                 deobfuscator,
	                 deobfuscator_sz,
	                 "(?s)%s=(function\\(a\\){.*return b.join\\(\"\"\\)};)",
	                 escaped)) {
		warn("Cannot find '%.*s' reference in base.js", (int)nsz, name);
		goto cleanup;
	}
	// debug("Got function body: %.*s", *deobfuscator_sz, *deobfuscator);
	debug("Got function body of size %zd", *deobfuscator_sz);

cleanup:; /* no particular cleanup to do (yet) */
}

static void
call_js_one(duk_context *ctx,
            const char *js_arg,
            struct call_ops *ops,
            void *userdata)
{
	/*
	 * Duplicate the compiled JavaScript function at the top of the Duktape
	 * stack. This is necessary because the upcoming duk_pcall() will
	 * essentially consume one copy of the compiled function; from the
	 * Duktape API docs:
	 *
	 *   The function and its arguments are replaced by a single return
	 *   value or a single error value.
	 *
	 * Duplicating the top of stack (TOS) therefore prepares us for
	 * successive invocations of this function in the near future.
	 */
	duk_dup_top(ctx);

	/*
	 * Push supplied argument onto the Duktape stack, and then call the
	 * compiled JavaScript function that is ready to go on the Duktape
	 * stack (set by a preceding duk_pcompile() in call_js_foreach()).
	 */
	duk_push_lstring(ctx, js_arg, strlen(js_arg));
	if (duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
		warn("Error in duk_pcall(): %s", peek(ctx));
		goto cleanup;
	}

	const char *result = duk_get_string(ctx, -1);
	if (result == NULL) {
		warn("Error fetching result of duk_pcall()");
		goto cleanup;
	}

	debug("Got JavaScript function result: %s", result);
	ops->got_result(result, strlen(result), userdata);

cleanup:
	duk_pop(ctx); /* <result> now points at free-d memory! */
	result = NULL;
}

void
call_js_foreach(const char *code,
                size_t sz,
                char **args,
                const size_t argc,
                struct call_ops *ops,
                void *userdata)
{
	duk_context *ctx = duk_create_heap_default(); /* may return NULL! */
	if (ctx == NULL) {
		warn("duk_create_heap_default() returned NULL");
		goto cleanup;
	}

	duk_push_lstring(ctx, code, sz);
	assert(duk_get_type(ctx, -1) == DUK_TYPE_STRING);

	duk_push_string(ctx, __FUNCTION__);
	if (duk_pcompile(ctx, DUK_COMPILE_FUNCTION) != 0) {
		warn("Error in duk_pcompile(): %s", peek(ctx));
		goto cleanup;
	}

	for (size_t i = 0; i < argc; ++i) {
		call_js_one(ctx, args[i], ops, userdata);
	}

cleanup:
	duk_destroy_heap(ctx); /* handles NULL gracefully */
}
