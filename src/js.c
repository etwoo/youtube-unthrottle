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

static void
pop(duk_context **ctx)
{
	duk_pop(*ctx);
}

static void
destroy_heap(duk_context **ctx)
{
	duk_destroy_heap(*ctx); /* handles NULL gracefully */
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

	duk_context *ctx __attribute__((cleanup(destroy_heap))) =
		duk_create_heap_default(); /* may return NULL! */
	error_if(ctx == NULL, "Cannot allocate Duktape heap");

	duk_push_lstring(ctx, json, json_sz);
	res = duk_safe_call(ctx, try_decode, NULL, 1, 1);
	if (res != DUK_EXEC_SUCCESS) {
		warn_then_return("Error in duk_json_decode(): %s", peek(ctx));
	}

	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1) ||
	    0 == duk_get_prop_literal(ctx, -1, "streamingData")) {
		warn_then_return("Cannot get .streamingData");
	}
	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1) ||
	    0 == duk_get_prop_literal(ctx, -1, "adaptiveFormats")) {
		warn_then_return("Cannot get .adaptiveFormats");
	}
	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1)) {
		warn_then_return("Cannot iterate over .adaptiveFormats");
	}

	bool got_video = false;
	bool got_audio = false;
	bool warned_about_signature_cipher = false;
	const duk_size_t sz = duk_get_length(ctx, -1);
	for (duk_size_t i = 0; i < sz; ++i) {
		/* get i-th element of adaptiveFormats array */
		duk_get_prop_index(ctx, -1, i);

		if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1)) {
			warn_then_return(".[%zd] is not object-coercible", i);
		}

		if (0 == duk_get_prop_literal(ctx, -1, "mimeType") ||
		    DUK_TYPE_STRING != duk_get_type(ctx, -1)) {
			warn_then_return("Cannot get .[%zd].mimeType", i);
		}

		if (0 == duk_get_prop_literal(ctx, -2, "url") ||
		    DUK_TYPE_STRING != duk_get_type(ctx, -1)) {
			warn_then_return("Cannot get .[%zd].url", i);
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
			warned_about_signature_cipher = true;
			info("signatureCipher is unsupported!");
		}
		duk_pop(ctx); /* for .signatureCipher */

		/* restore stack, to prepare for (i+1)-th element */
		duk_pop_3(ctx);
	}

	duk_pop_2(ctx); /* for .streamingData.adaptiveFormats */
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
		info("Cannot find base.js URL in HTML document");
	} else {
		debug("Parsed base.js URI: %.*s", (int)*basejs_sz, *basejs);
	}
}

long long int
find_js_timestamp(const char *js, size_t sz)
{
	const char *ts = NULL;
	size_t ts_sz = 0;
	if (!re_capture("signatureTimestamp:([0-9]+)", js, sz, &ts, &ts_sz)) {
		warn_then_return_negative_1("Cannot find timestamp in base.js");
	}

	/*
	 * strtoll() does not modify errno on success, so we must clear it
	 * explicitly if we want a predictable value.
	 */
	errno = 0;

	long long int res = strtoll(ts, NULL, 10);
	if (errno != 0) {
		warn_then_return_negative_1("strtoll() error on %.*s: %s",
		                            (int)ts_sz,
		                            ts,
		                            strerror(errno));
	}

	debug("Parsed signatureTimestamp %.*s into %lld", (int)ts_sz, ts, res);
	return res;
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
		info("Cannot find '%s' in base.js", RE_FUNC_NAME[i]);
	}
	if (name == NULL || nsz == 0) {
		return;
	}
	debug("Got function name 1: %.*s", (int)nsz, name);

	if (!re_pattern_escape(name, nsz, escaped, sizeof(escaped))) {
		return;
	}
	debug("Escaped function name 1: %s", escaped);

	if (!re_capturef(js,
	                 js_sz,
	                 &name,
	                 &nsz,
	                 "var %s=\\[([^\\]]+)\\]",
	                 escaped)) {
		warn_then_return("Cannot find %.*s in base.js", (int)nsz, name);
	}
	debug("Got function name 2: %.*s", (int)nsz, name);

	if (!re_pattern_escape(name, nsz, escaped, sizeof(escaped))) {
		return;
	}
	debug("Escaped function name 2: %s", escaped);

	if (!re_capturef(js,
	                 js_sz,
	                 deobfuscator,
	                 deobfuscator_sz,
	                 "(?s)%s=(function\\(a\\){.*return b.join\\(\"\"\\)};)",
	                 escaped)) {
		warn_then_return("Cannot find %.*s in base.js", (int)nsz, name);
	}
	// debug("Got function body: %.*s", *deobfuscator_sz, *deobfuscator);
	debug("Got function body of size %zd", *deobfuscator_sz);
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

	duk_context *guard __attribute__((cleanup(pop))) = ctx;

	/*
	 * Push supplied argument onto the Duktape stack, and then call the
	 * compiled JavaScript function that is ready to go on the Duktape
	 * stack (set by a preceding duk_pcompile() in call_js_foreach()).
	 */
	duk_push_lstring(ctx, js_arg, strlen(js_arg));
	if (duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
		warn_then_return("Error in duk_pcall(): %s", peek(ctx));
	}

	const char *result = duk_get_string(ctx, -1);
	if (result == NULL) {
		warn_then_return("Error fetching function result");
	}

	debug("Got JavaScript function result: %s", result);
	ops->got_result(result, strlen(result), userdata);
}

void
call_js_foreach(const char *code,
                size_t sz,
                char **args,
                const size_t argc,
                struct call_ops *ops,
                void *userdata)
{
	duk_context *ctx __attribute__((cleanup(destroy_heap))) =
		duk_create_heap_default(); /* may return NULL! */
	error_if(ctx == NULL, "Cannot allocate Duktape heap");

	duk_push_lstring(ctx, code, sz);
	assert(duk_get_type(ctx, -1) == DUK_TYPE_STRING);

	duk_push_string(ctx, __FUNCTION__);
	if (duk_pcompile(ctx, DUK_COMPILE_FUNCTION) != 0) {
		warn_then_return("Error in duk_pcompile(): %s", peek(ctx));
	}

	for (size_t i = 0; i < argc; ++i) {
		call_js_one(ctx, args[i], ops, userdata);
	}
}
