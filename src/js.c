#include "js.h"

#include "array.h"
#include "debug.h"
#include "re.h"

#include <assert.h>
#include <stdbool.h>

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
parse_json(const struct string_view *json, const struct parse_ops *ops)
{
	// debug("Got JSON blob: %.*s", json->sz, json->data);
	debug("Got JSON blob of size %zd", json->sz);

	json_error_t json_error;

	json_auto_t *obj = json_loadb(json->data, json->sz, 0, &json_error);
	if (obj == NULL) {
		return make_result(ERR_JS_PARSE_JSON_DECODE, json_error.text);
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
		assert(url != NULL);

		bool choose_quality = true;
		json_t *quality = json_object_get(cur, "qualityLabel");
		if (json_is_string(quality)) {
			const char *q = json_string_value(quality);
			assert(q != NULL);
			void *ud = ops->choose_quality_userdata;
			auto_result err = ops->choose_quality(q, ud);
			choose_quality = (err.err == OK);
		}

		if (choose_quality &&
		    0 == strncmp(mimetype, MTVIDEO, strlen(MTVIDEO)) &&
		    false == got_video) {
			check(ops->got_video(url, ops->got_video_userdata));
			got_video = true;
		}
		if (choose_quality &&
		    0 == strncmp(mimetype, MTAUDIO, strlen(MTAUDIO)) &&
		    false == got_audio) {
			check(ops->got_audio(url, ops->got_audio_userdata));
			got_audio = true;
		}

		/*
		 * Check for <streamingCipher> attribute, which we do not
		 * currently support. Streams with a <streamingCipher>
		 * attribute instead of a plaintext <url> value require more
		 * deobfuscation logic, distinct from n-parameter decoding.
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
	struct string_view id = {0};
	struct string_view url = {.data = target_url, .sz = strlen(target_url)};

	/* Note use of non-capturing group: (?:...) */
	check(re_capture("(?:&|\\?)v=([^&]+)(?:&|$)", &url, &id));
	if (id.data == NULL) {
		return make_result(ERR_JS_MAKE_INNERTUBE_JSON_ID);
	}
	debug("Parsed ID: %.*s", (int)id.sz, id.data);

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
	                id.data,
	                id.sz,
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
find_base_js_url(const struct string_view *html, struct string_view *basejs)
{
	check(re_capture("\"(/s/player/[^\"]+/base.js)\"", html, basejs));
	if (basejs->data == NULL) {
		return make_result(ERR_JS_BASEJS_URL_FIND);
	}

	debug("Parsed base.js URI: %.*s", (int)basejs->sz, basejs->data);
	return RESULT_OK;
}

result_t
find_js_timestamp(const struct string_view *js, long long int *value)
{
	struct string_view ts = {0};
	check(re_capture("signatureTimestamp:([0-9]+)", js, &ts));
	if (ts.data == NULL) {
		return make_result(ERR_JS_TIMESTAMP_FIND);
	}

	/*
	 * strtoll() does not update errno on success, so we must clear it
	 * explicitly if we want a predictable value.
	 */
	errno = 0;

	long long int res = strtoll(ts.data, NULL, 10);
	if (errno != 0) {
		return make_result(ERR_JS_TIMESTAMP_PARSE_LL,
		                   errno,
		                   ts.data,
		                   ts.sz);
	}

	debug("Parsed timestamp %.*s into %lld", (int)ts.sz, ts.data, res);
	*value = res;
	return RESULT_OK;
}

result_t
find_js_deobfuscator_magic_global(const struct string_view *js,
                                  struct string_view *magic)
{
	check(re_capture("(var [^ =]+=[-0-9]{6,});", js, magic));
	if (magic->data == NULL) {
		return make_result(ERR_JS_DEOBFUSCATOR_MAGIC_FIND);
	}

	debug("Parsed deobfuscator magic: %.*s", (int)magic->sz, magic->data);
	return RESULT_OK;
}

static void
asprintf_free(char **strp)
{
	free(*strp);
}

/*
 * Based on: youtube-dl, yt-dlp, rusty_ytdl
 *
 * find_js_deobfuscator() does the following:
 *
 * 1) find <foo> in base.js like: &&(b=foo[0](b)
 * 2) find <bar> in base.js like: var foo=[bar]
 * 3) find <...> in base.js like: bar=function(a){...}
 *
 * Later code uses the resulting function body like:
 *
 * 4) eval JavaScript fragment like: function(a){...}([$n_param])
 * 5) use return value from step 4 as decoded n-parameter
 */
result_t
find_js_deobfuscator(const struct string_view *js,
                     struct string_view *deobfuscator)
{
	int rc = 0;
	struct string_view n = {0};

	check(re_capture("&&\\([[:alpha:]]=([^\\]]+)\\[0\\]\\([[:alpha:]]\\)",
	                 js,
	                 &n));
	if (n.data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_ONE);
	}
	debug("Got function name 1: %.*s", (int)n.sz, n.data);

	char *p2 __attribute__((cleanup(asprintf_free))) = NULL;
	rc = asprintf(&p2, "var \\Q%.*s\\E=\\[([^\\]]+)\\]", (int)n.sz, n.data);
	check_if(rc < 0, ERR_JS_DEOBFUSCATOR_ALLOC);

	check(re_capture(p2, js, &n));
	if (n.data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_TWO, n.data, n.sz);
	}
	debug("Got function name 2: %.*s", (int)n.sz, n.data);

	char *p3 __attribute__((cleanup(asprintf_free))) = NULL;
	rc = asprintf(&p3,
	              "(?s)\\n\\Q%.*s\\E=("
	              "function\\([[:alpha:]]\\){.*"
	              "(?!\\n[^=\\n]+=)" /* stop before next global var decl */
	              "return [[:alpha:]]\\.join\\(\"\"\\)"
	              "};"
	              ")",
	              (int)n.sz,
	              n.data);
	check_if(rc < 0, ERR_JS_DEOBFUSCATOR_ALLOC);

	check(re_capture(p3, js, deobfuscator));
	if (deobfuscator->data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_BODY, n.data, n.sz);
	}

	// debug("Got func body: %.*s", deobfuscator->sz, deobfuscator->data);
	debug("Got function body of size %zd", deobfuscator->sz);
	return RESULT_OK;
}

static WARN_UNUSED result_t
call_js_one(duk_context *ctx,
            const char *js_arg,
            size_t js_pos,
            const struct call_ops *ops,
            void *userdata)
{
	/*
	 * Duplicate the compiled JavaScript function at the top of the Duktape
	 * stack, to prepare for the upcoming duk_pcall() that consumes one
	 * copy of the compiled function; from the Duktape API docs:
	 *
	 *   The function and its arguments [get] replaced by a single return
	 *   value or a single error value.
	 *
	 * Duplicating the top of stack (TOS) thus prepares us for successive
	 * invocations of this function.
	 */
	duk_dup_top(ctx);

	duk_context *guard __attribute__((cleanup(pop))) = ctx;

	/*
	 * Push supplied argument onto the Duktape stack, and then call the
	 * compiled, ready-to-use JavaScript function on the Duktape stack (set
	 * by a preceding duk_pcompile() in call_js_foreach()).
	 */
	duk_push_lstring(ctx, js_arg, strlen(js_arg));
	if (duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
		return make_result(ERR_JS_CALL_INVOKE, peek(ctx));
	}

	const char *result = duk_get_string(ctx, -1);
	if (result == NULL) {
		return make_result(ERR_JS_CALL_GET_RESULT);
	}

	debug("Got JavaScript function result: %s", result);
	check(ops->got_result(result, js_pos, userdata));

	return RESULT_OK;
}

result_t
call_js_foreach(const struct string_view *magic,
                const struct string_view *code,
                char **args,
                const struct call_ops *ops,
                void *userdata)
{
	duk_context *ctx __attribute__((cleanup(destroy_heap))) =
		duk_create_heap_default(); /* may return NULL! */
	check_if(ctx == NULL, ERR_JS_CALL_ALLOC);

	duk_eval_lstring_noresult(ctx, magic->data, magic->sz);

	duk_push_lstring(ctx, code->data, code->sz);
	assert(duk_get_type(ctx, -1) == DUK_TYPE_STRING);

	duk_push_string(ctx, __func__);
	if (duk_pcompile(ctx, DUK_COMPILE_FUNCTION) != 0) {
		return make_result(ERR_JS_CALL_COMPILE, peek(ctx));
	}

	for (size_t i = 0; args[i]; ++i) {
		check(call_js_one(ctx, args[i], i, ops, userdata));
	}

	return RESULT_OK;
}
