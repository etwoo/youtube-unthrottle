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

/*
 * Some helpful Jansson references:
 *
 *   https://jansson.readthedocs.io/en/latest/apiref.html
 */
#include <jansson.h>

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

static const char MTVIDEO[] = "video/";
static const char MTAUDIO[] = "audio/";

result_t
parse_json(const char *json, size_t json_sz, struct parse_ops *ops)
{
	// debug("Got JSON blob: %.*s", json_sz, json);
	debug("Got JSON blob of size %zd", json_sz);

	json_error_t json_error;

	json_auto_t *obj = json_loadb(json, json_sz, 0, &json_error);
	if (obj == NULL) {
		return make_result(ERR_JS_PARSE_JSON_DECODE,
		                   (const char *)json_error.text);
	} else if (!json_is_object(obj)) {
		return make_result(ERR_JS_PARSE_JSON_GET_STREAMINGDATA);
	}

	json_t *streamingData = json_object_get(obj, "streamingData");
	if (streamingData == NULL) {
		return make_result(ERR_JS_PARSE_JSON_GET_STREAMINGDATA);
	} else if (!json_is_object(streamingData)) {
		return make_result(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS);
	}

	json_t *adaptiveFormats =
		json_object_get(streamingData, "adaptiveFormats");
	if (adaptiveFormats == NULL) {
		return make_result(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS);
	} else if (!json_is_array(adaptiveFormats)) {
		return make_result(ERR_JS_PARSE_JSON_ADAPTIVEFORMATS_TYPE);
	}

	bool got_video = false;
	bool got_audio = false;
	bool warned_about_signature_cipher = false;

	size_t i = 0;
	json_t *cur = NULL;
	json_array_foreach (adaptiveFormats, i, cur) {
		if (!json_is_object(cur)) {
			return make_result(ERR_JS_PARSE_JSON_ELEM_TYPE);
		}

		json_t *json_mimetype = json_object_get(cur, "mimeType");
		if (!json_is_string(json_mimetype)) {
			return make_result(ERR_JS_PARSE_JSON_ELEM_MIMETYPE);
		}
		const char *mimetype = json_string_value(json_mimetype);
		assert(mimetype != NULL);

		json_t *json_url = json_object_get(cur, "url");
		if (!json_is_string(json_url)) {
			return make_result(ERR_JS_PARSE_JSON_ELEM_URL);
		}
		const char *url = json_string_value(json_url);
		const size_t uz = json_string_length(json_url);
		assert(url != NULL);

		bool choose_quality = true;
		json_t *quality = json_object_get(cur, "qualityLabel");
		if (json_is_string(quality)) {
			const char *q = json_string_value(quality);
			assert(q != NULL);
			const size_t qz = json_string_length(quality);
			void *ud = ops->choose_quality_userdata;
			result_t err = ops->choose_quality(q, qz, ud);
			choose_quality = (err.err == OK);
		}

		if (choose_quality &&
		    0 == strncmp(mimetype, MTVIDEO, strlen(MTVIDEO)) &&
		    false == got_video) {
			check(ops->got_video(url, uz, ops->got_video_userdata));
			got_video = true;
		}
		if (choose_quality &&
		    0 == strncmp(mimetype, MTAUDIO, strlen(MTAUDIO)) &&
		    false == got_audio) {
			check(ops->got_audio(url, uz, ops->got_audio_userdata));
			got_audio = true;
		}

		/*
		 * Check for streamingCipher attribute, which we do not
		 * currently support. Streams with a "streamingCipher"
		 * attribute instead of a plaintext "url" value require
		 * additional deobfuscation logic, similar to (but distinct
		 * from) n-parameter decoding.
		 * */
		json_t *get_streaming_cipher =
			json_object_get(cur, "signatureCipher");
		if (get_streaming_cipher && !warned_about_signature_cipher) {
			warned_about_signature_cipher = true;
			info("signatureCipher is unsupported!");
		}
	}

	return RESULT_OK;
}

result_t
make_innertube_json(const char *target_url,
                    const char *proof_of_origin,
                    long long int timestamp,
                    char **body)
{
	const char *id = NULL;
	size_t sz = 0;

	/* Note use of non-capturing group: (?:...) */
	if (!re_capture("(?:&|\\?)v=([^&]+)(?:&|$)",
	                target_url,
	                strlen(target_url),
	                &id,
	                &sz)) {
		return make_result(ERR_JS_MAKE_INNERTUBE_JSON_ID);
	}
	debug("Parsed ID: %.*s", (int)sz, id);

	json_auto_t *obj = NULL;
	obj = json_pack("{s{s{ss,ss,ss,ss,si}},ss%,s{ss},s{s{ss,si}},sb,sb}",
	                "context",
	                "client",
	                "clientName",
	                "WEB",
	                "clientVersion",
	                "2.20240726.00.00",
	                "hl",
	                "en",
	                "timeZone",
	                "UTC",
	                "utcOffsetMinutes",
	                0,
	                "videoId",
	                id,
	                sz,
	                "serviceIntegrityDimensions",
	                "poToken",
	                proof_of_origin,
	                "playbackContext",
	                "contentPlaybackContext",
	                "html5Preference",
	                "HTML5_PREF_WANTS",
	                "signatureTimestamp",
	                timestamp,
	                "contentCheckOk",
	                1,
	                "racyCheckOk",
	                1);
	check_if(obj == NULL, ERR_JS_MAKE_INNERTUBE_JSON_ALLOC);

	*body = json_dumps(obj, JSON_COMPACT);
	check_if(*body == NULL, ERR_JS_MAKE_INNERTUBE_JSON_ALLOC);

	debug("Formatted InnerTube POST body: %s", *body);
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
		return make_result(ERR_JS_BASEJS_URL_FIND);
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
		return make_result(ERR_JS_TIMESTAMP_FIND);
	}

	/*
	 * strtoll() does not modify errno on success, so we must clear it
	 * explicitly if we want a predictable value.
	 */
	errno = 0;

	long long int res = strtoll(ts, NULL, 10);
	if (errno != 0) {
		return make_result(ERR_JS_TIMESTAMP_PARSE_LL, errno, ts, tsz);
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
		return make_result(ERR_JS_DEOB_FIND_FUNCTION_ONE);
	}
	debug("Got function name 1: %.*s", (int)nsz, name);

	char *p2 __attribute__((cleanup(asprintf_free))) = NULL;
	rc = asprintf(&p2, "var \\Q%.*s\\E=\\[([^\\]]+)\\]", (int)nsz, name);
	check_if(rc < 0, ERR_JS_DEOBFUSCATOR_ALLOC);

	if (!re_capture(p2, js, js_sz, &name, &nsz)) {
		return make_result(ERR_JS_DEOB_FIND_FUNCTION_TWO, name, nsz);
	}
	debug("Got function name 2: %.*s", (int)nsz, name);

	char *p3 __attribute__((cleanup(asprintf_free))) = NULL;
	rc = asprintf(&p3,
	              "(?s)\\Q%.*s\\E=("
	              "function\\(a\\){.*return b.join\\(\"\"\\)};"
	              ")",
	              (int)nsz,
	              name);
	check_if(rc < 0, ERR_JS_DEOBFUSCATOR_ALLOC);

	if (!re_capture(p3, js, js_sz, deobfuscator, deobfuscator_sz)) {
		return make_result(ERR_JS_DEOB_FIND_FUNCTION_BODY, name, nsz);
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
		return make_result(ERR_JS_CALL_INVOKE, peek(ctx));
	}

	const char *result = duk_get_string(ctx, -1);
	check_if(result == NULL, ERR_JS_CALL_GET_RESULT);

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
	check_if(ctx == NULL, ERR_JS_CALL_ALLOC);

	duk_push_lstring(ctx, code, sz);
	assert(duk_get_type(ctx, -1) == DUK_TYPE_STRING);

	duk_push_string(ctx, __FUNCTION__);
	if (duk_pcompile(ctx, DUK_COMPILE_FUNCTION) != 0) {
		return make_result(ERR_JS_CALL_COMPILE, peek(ctx));
	}

	for (size_t i = 0; i < argc; ++i) {
		check(call_js_one(ctx, args[i], i, ops, userdata));
	}

	return RESULT_OK;
}
