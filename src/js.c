#include "js.h"

#include "array.h"
#include "debug.h"
#include "re.h"
#include "result_type.h"

#include <assert.h>

/*
 * Some helpful Duktape references:
 *
 *   https://duktape.org/api
 */
#include <duktape.h>

/*
 * Set up codegen macros for module-specific result_t.
 */
#define LITERAL(str) s = strdup(str)
#define GET_DETAILS(x) x->details ? x->details : "[Cannot allocate details]"
#define DETAILS(fmt) printed = asprintf(&s, fmt, GET_DETAILS(p))
#define DETAILS_WITH_STRERROR(fmt)                                             \
	printed = asprintf(&s, fmt, GET_DETAILS(p), strerror(p->num))

#define ERROR_TABLE(X)                                                         \
	X(OK, LITERAL("Success in " __FILE_NAME__))                            \
	X(ERR_PARSE_JSON_ALLOC_HEAP,                                           \
	  LITERAL("Cannot allocate JavaScript interpreter heap"))              \
	X(ERR_PARSE_JSON_DECODE, DETAILS("Error in duk_json_decode(): %s"))    \
	X(ERR_PARSE_JSON_GET_STREAMINGDATA,                                    \
	  LITERAL("Cannot get .streamingData"))                                \
	X(ERR_PARSE_JSON_GET_ADAPTIVEFORMATS,                                  \
	  LITERAL("Cannot get .adaptiveFormats"))                              \
	X(ERR_PARSE_JSON_ADAPTIVEFORMATS_TYPE,                                 \
	  LITERAL("Cannot iterate over .adaptiveFormats"))                     \
	X(ERR_PARSE_JSON_ELEM_TYPE,                                            \
	  LITERAL("adaptiveFormats element is not object-coercible"))          \
	X(ERR_PARSE_JSON_ELEM_MIMETYPE,                                        \
	  LITERAL("Cannot get mimeType of adaptiveFormats element"))           \
	X(ERR_PARSE_JSON_ELEM_URL,                                             \
	  LITERAL("Cannot get url of adaptiveFormats element"))                \
	X(ERR_BASEJS_URL_FIND,                                                 \
	  LITERAL("Cannot find base.js URL in HTML document"))                 \
	X(ERR_TIMESTAMP_FIND, LITERAL("Cannot find timestamp in base.js"))     \
	X(ERR_TIMESTAMP_PARSE_TO_LONGLONG,                                     \
	  DETAILS_WITH_STRERROR("Error in strtoll() on %s: %s"))               \
	X(ERR_DEOBFUSCATOR_ALLOC, LITERAL("Cannot allocate asprintf buffer"))  \
	X(ERR_DEOBFUSCATOR_FIND_FUNCTION_ONE,                                  \
	  LITERAL("Cannot find deobfuscation function in base.js"))            \
	X(ERR_DEOBFUSCATOR_FIND_FUNCTION_TWO,                                  \
	  DETAILS("Cannot find reference to %s in base.js"))                   \
	X(ERR_DEOBFUSCATOR_FIND_FUNCTION_BODY,                                 \
	  DETAILS("Cannot find body of %s in base.js"))                        \
	X(ERR_CALL_ALLOC,                                                      \
	  LITERAL("Cannot allocate JavaScript interpreter heap"))              \
	X(ERR_CALL_COMPILE, DETAILS("Error in duk_pcompile(): %s"))            \
	X(ERR_CALL_INVOKE, DETAILS("Error in duk_pcall(): %s"))                \
	X(ERR_CALL_GET_RESULT, LITERAL("Error fetching function result"))

#define ERROR_EXAMPLE_ARGS 0,strdup("foobar")

#define DO_CLEANUP free(p->details)
#define DO_INIT {.err = err, .num = num, .details = s}

/*
 * Extend `struct result_base` to create a module-specific result_t.
 */
struct result_js {
	struct result_base base;
	enum { ERROR_TABLE(INTO_ENUM) } err;
	int num;
	char *details;
};
DEFINE_RESULT(result_js, DO_CLEANUP, DO_INIT, int err, int num, char *s)

static result_t WARN_UNUSED
make_result(int err_type, char *details)
{
	return make_result_js(err_type, 0, details);
}

static WARN_UNUSED const char *
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
static WARN_UNUSED duk_ret_t
try_decode(duk_context *ctx, void *udata __attribute__((unused)))
{
	duk_json_decode(ctx, -1);
	return 1;
}

static const char MTVIDEO[] = "video/";
static const char MTAUDIO[] = "audio/";

result_t
parse_json(const char *json,
           size_t json_sz,
           struct parse_ops *ops,
           void *userdata)
{
	// debug("Got JSON blob: %.*s", json_sz, json);
	debug("Got JSON blob of size %zd", json_sz);

	duk_context *ctx __attribute__((cleanup(destroy_heap))) =
		duk_create_heap_default(); /* may return NULL! */
	if (ctx == NULL) {
		return make_result(ERR_PARSE_JSON_ALLOC_HEAP, NULL);
	}

	duk_push_lstring(ctx, json, json_sz);
	duk_ret_t res = duk_safe_call(ctx, try_decode, NULL, 1, 1);
	if (res != DUK_EXEC_SUCCESS) {
		return make_result(ERR_PARSE_JSON_DECODE, strdup(peek(ctx)));
	}

	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1) ||
	    0 == duk_get_prop_literal(ctx, -1, "streamingData")) {
		return make_result(ERR_PARSE_JSON_GET_STREAMINGDATA, NULL);
	}
	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1) ||
	    0 == duk_get_prop_literal(ctx, -1, "adaptiveFormats")) {
		return make_result(ERR_PARSE_JSON_GET_ADAPTIVEFORMATS, NULL);
	}
	if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1)) {
		return make_result(ERR_PARSE_JSON_ADAPTIVEFORMATS_TYPE, NULL);
	}

	bool got_video = false;
	bool got_audio = false;
	bool warned_about_signature_cipher = false;
	const duk_size_t sz = duk_get_length(ctx, -1);
	for (duk_size_t i = 0; i < sz; ++i) {
		/* get i-th element of adaptiveFormats array */
		duk_get_prop_index(ctx, -1, i);

		if (DUK_TYPE_OBJECT != duk_get_type(ctx, -1)) {
			return make_result(ERR_PARSE_JSON_ELEM_TYPE, NULL);
		}

		if (0 == duk_get_prop_literal(ctx, -1, "mimeType") ||
		    DUK_TYPE_STRING != duk_get_type(ctx, -1)) {
			return make_result(ERR_PARSE_JSON_ELEM_MIMETYPE, NULL);
		}

		if (0 == duk_get_prop_literal(ctx, -2, "url") ||
		    DUK_TYPE_STRING != duk_get_type(ctx, -1)) {
			return make_result(ERR_PARSE_JSON_ELEM_URL, NULL);
		}

		const char *url = duk_get_string(ctx, -1);
		const char *mimetype = duk_get_string(ctx, -2);
		assert(url != NULL && mimetype != NULL);

		if (0 == strncmp(mimetype, MTVIDEO, strlen(MTVIDEO)) &&
		    false == got_video) {
			check(ops->got_video(url, strlen(url), userdata));
			got_video = true;
		}
		if (0 == strncmp(mimetype, MTAUDIO, strlen(MTAUDIO)) &&
		    false == got_audio) {
			check(ops->got_audio(url, strlen(url), userdata));
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
	return RESULT_OK;
}

result_t
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
		return make_result(ERR_BASEJS_URL_FIND, NULL);
	}

	debug("Parsed base.js URI: %.*s", (int)*basejs_sz, *basejs);
	return RESULT_OK;
}

result_t
find_js_timestamp(const char *js, size_t js_sz, long long int *value)
{
	const char *ts = NULL;
	size_t tsz = 0;
	if (!re_capture("signatureTimestamp:([0-9]+)", js, js_sz, &ts, &tsz)) {
		return make_result(ERR_TIMESTAMP_FIND, NULL);
	}

	/*
	 * strtoll() does not modify errno on success, so we must clear it
	 * explicitly if we want a predictable value.
	 */
	errno = 0;

	long long int res = strtoll(ts, NULL, 10);
	if (errno != 0) {
		return make_result_js(ERR_TIMESTAMP_PARSE_TO_LONGLONG,
		                      errno,
		                      strndup(ts, tsz));
	}

	debug("Parsed signatureTimestamp %.*s into %lld", (int)tsz, ts, res);
	*value = res;
	return RESULT_OK;
}

static void
asprintf_free(char **strp)
{
	free(*strp);
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
result_t
find_js_deobfuscator(const char *js,
                     size_t js_sz,
                     const char **deobfuscator,
                     size_t *deobfuscator_sz)
{
	int rc = 0;

	const char *name = NULL;
	size_t nsz = 0;
	for (size_t i = 0; i < ARRAY_SIZE(RE_FUNC_NAME); ++i) {
		if (re_capture(RE_FUNC_NAME[i], js, js_sz, &name, &nsz)) {
			break;
		}
		info("Cannot find '%s' in base.js", RE_FUNC_NAME[i]);
	}
	if (name == NULL || nsz == 0) {
		return make_result(ERR_DEOBFUSCATOR_FIND_FUNCTION_ONE, NULL);
	}
	debug("Got function name 1: %.*s", (int)nsz, name);

	char *p2 __attribute__((cleanup(asprintf_free))) = NULL;
	rc = asprintf(&p2, "var \\Q%.*s\\E=\\[([^\\]]+)\\]", (int)nsz, name);
	if (rc < 0) {
		return make_result(ERR_DEOBFUSCATOR_ALLOC, NULL);
	}

	if (!re_capture(p2, js, js_sz, &name, &nsz)) {
		return make_result(ERR_DEOBFUSCATOR_FIND_FUNCTION_TWO,
		                   strndup(name, nsz));
	}
	debug("Got function name 2: %.*s", (int)nsz, name);

	char *p3 __attribute__((cleanup(asprintf_free))) = NULL;
	rc = asprintf(&p3,
	              "(?s)\\Q%.*s\\E=("
	              "function\\(a\\){.*return b.join\\(\"\"\\)};"
	              ")",
	              (int)nsz,
	              name);
	if (rc < 0) {
		return make_result(ERR_DEOBFUSCATOR_ALLOC, NULL);
	}

	if (!re_capture(p3, js, js_sz, deobfuscator, deobfuscator_sz)) {
		return make_result(ERR_DEOBFUSCATOR_FIND_FUNCTION_BODY,
		                   strndup(name, nsz));
	}

	// debug("Got function body: %.*s", *deobfuscator_sz, *deobfuscator);
	debug("Got function body of size %zd", *deobfuscator_sz);
	return RESULT_OK;
}

static WARN_UNUSED result_t
call_js_one(duk_context *ctx,
            const char *js_arg,
            size_t js_pos,
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
		return make_result(ERR_CALL_INVOKE, strdup(peek(ctx)));
	}

	const char *result = duk_get_string(ctx, -1);
	if (result == NULL) {
		return make_result(ERR_CALL_GET_RESULT, NULL);
	}

	debug("Got JavaScript function result: %s", result);
	check(ops->got_result(result, strlen(result), js_pos, userdata));

	return RESULT_OK;
}

result_t
call_js_foreach(const char *code,
                size_t sz,
                char **args,
                const size_t argc,
                struct call_ops *ops,
                void *userdata)
{
	duk_context *ctx __attribute__((cleanup(destroy_heap))) =
		duk_create_heap_default(); /* may return NULL! */
	if (ctx == NULL) {
		return make_result(ERR_CALL_ALLOC, NULL);
	}

	duk_push_lstring(ctx, code, sz);
	assert(duk_get_type(ctx, -1) == DUK_TYPE_STRING);

	duk_push_string(ctx, __FUNCTION__);
	if (duk_pcompile(ctx, DUK_COMPILE_FUNCTION) != 0) {
		return make_result(ERR_CALL_COMPILE, strdup(peek(ctx)));
	}

	for (size_t i = 0; i < argc; ++i) {
		check(call_js_one(ctx, args[i], i, ops, userdata));
	}

	return RESULT_OK;
}

#undef DO_CLEANUP
#undef DO_INIT
#undef ERROR_TABLE
#undef GET_DETAILS
#undef DETAILS_WITH_STRERROR
#undef DETAILS
#undef LITERAL
