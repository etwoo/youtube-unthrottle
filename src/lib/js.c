#include "lib/js.h"

#include "lib/re.h"
#include "sys/array.h"
#include "sys/debug.h"

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

static void
str_free(char **strp)
{
	free(*strp);
}

/*
 * Copy <in> to <out>, while excluding newlines.
 */
static void
pretty_print_code(struct string_view in /* note: pass by value */, char **out)
{
#ifdef WITH_DEBUG_LOG
	char *buffer = malloc((in.sz + 1) * sizeof(*buffer));
	*out = buffer;
	while (buffer) {
		const char *src_end = memchr(in.data, '\n', in.sz);
		if (src_end == NULL) {
			memcpy(buffer, in.data, in.sz);
			buffer[in.sz] = '\0';
			break;
		}

		size_t n = src_end - in.data;
		memcpy(buffer, in.data, n);

		buffer += n;
		n++; /* skip newline char in <in.data> */
		in.data += n;
		in.sz -= n;
	}
#else
	(void)in;
	*out = strdup("PRETTY_PRINT_NOT_IMPLEMENTED");
#endif
}

static const char MTVIDEO[] = "video/";

result_t
parse_json(const struct string_view *json,
           const struct parse_ops *ops,
           struct parse_values *values)
{
	// debug("Got JSON blob: %.*s", json->sz, json->data);
	debug("Got JSON blob of size %zu", json->sz);

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

	values->itag = -1; /* set sentinel value */

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

		if (0 != strncmp(mimetype, MTVIDEO, strlen(MTVIDEO))) {
			continue;
		}

		json_t *quality = json_object_get(cur, "qualityLabel");
		if (!json_is_string(quality)) {
			continue;
		}

		const char *q = json_string_value(quality);
		assert(q != NULL);

		auto_result chosen =
			ops->choose_quality
				? ops->choose_quality(q, ops->userdata)
				: RESULT_OK;
		if (chosen.err != OK) {
			continue;
		}

		json_t *json_itag = json_object_get(cur, "itag");
		if (!json_is_integer(json_itag)) {
			return make_result(ERR_JS_PARSE_JSON_ELEM_ITAG);
		}

		values->itag = json_integer_value(json_itag);
		debug("Parsed itag=%lld", values->itag);
		break;
	}

	if (values->itag < 0) {
		return make_result(ERR_JS_PARSE_JSON_NO_MATCH);
	}

	json_t *serverAbrStreamingUrl =
		json_object_get(obj, "serverAbrStreamingUrl");
	if (!json_is_string(serverAbrStreamingUrl)) {
		return make_result(ERR_JS_SABR_URL_FIND);
	}
	values->sabr_url = strndup(json_string_value(serverAbrStreamingUrl),
	                           json_string_length(serverAbrStreamingUrl));
	debug("Parsed SABR URI: %p %s", values->sabr_url, values->sabr_url);

	json_t *videoPlaybackUstreamerConfig =
		json_object_get(obj, "videoPlaybackUstreamerConfig");
	if (!json_is_string(videoPlaybackUstreamerConfig)) {
		return make_result(ERR_JS_PLAYBACK_CONFIG_FIND);
	}
	values->playback_config =
		strndup(json_string_value(videoPlaybackUstreamerConfig),
	                json_string_length(videoPlaybackUstreamerConfig));
	debug("Parsed playback config: %s", values->playback_config);

	return RESULT_OK;
}

void
parse_values_cleanup(struct parse_values *p)
{
	if (p) {
		free(p->sabr_url);
		free(p->playback_config);
	}
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
                                  struct deobfuscator *d)
{
	check(re_capture("(var [^\\s=]+=[-0-9]{6,});", js, d->magic));
	if (d->magic[0].data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_MAGIC_ONE);
	}

	debug("Parsed magic 1: %.*s", (int)d->magic[0].sz, d->magic[0].data);

	check(re_capture("(?s)use strict[^;];"
	                 "(.*?),\\n?"   /* Lazily capture all JavaScript code */
	                 "(?:"          /* ... until we hit a long enough run */
	                 "[^\\s]{2,3}," /* of consecutive var declarations.   */
	                 "){7}",        /* Current threshold: 7 variables     */
	                 js,
	                 d->magic + 1));
	if (d->magic[1].data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_MAGIC_TWO);
	}

	char *pretty_print __attribute__((cleanup(str_free))) = NULL;
	pretty_print_code(d->magic[1], &pretty_print);
	debug("Parsed magic 2: %s", pretty_print);

	return RESULT_OK;
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
find_js_deobfuscator(const struct string_view *js, struct deobfuscator *d)
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

	char *p2 __attribute__((cleanup(str_free))) = NULL;
	rc = asprintf(&p2, "var \\Q%.*s\\E=\\[([^\\]]+)\\]", (int)n.sz, n.data);
	check_if(rc < 0, ERR_JS_DEOBFUSCATOR_ALLOC);

	check(re_capture(p2, js, &n));
	if (n.data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_TWO, n.data, n.sz);
	}
	debug("Got function name 2: %.*s", (int)n.sz, n.data);

	char *p3 __attribute__((cleanup(str_free))) = NULL;
	rc = asprintf(&p3,
	              "(?s)\\n\\Q%.*s\\E=("
	              "function\\([[:alpha:]]\\){"
	              ".*?" /* lazy (not greedy) quantifier: `*?` */
	              "};"
	              ")"
	              "\\n[^\\s=]+=", /* stop before next global var decl */
	              (int)n.sz,
	              n.data);
	check_if(rc < 0, ERR_JS_DEOBFUSCATOR_ALLOC);

	check(re_capture(p3, js, &d->code));
	if (d->code.data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_BODY, n.data, n.sz);
	}

	char *pretty_print __attribute__((cleanup(str_free))) = NULL;
	pretty_print_code(d->code, &pretty_print);
	debug("Got function body of %.*s=%s", (int)n.sz, n.data, pretty_print);

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

	duk_context *guard // NOLINT(clang-analyzer-deadcode.DeadStores)
		__attribute__((cleanup(pop))) = ctx;

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
call_js_foreach(const struct deobfuscator *d,
                char **args,
                const struct call_ops *ops,
                void *userdata)
{
	duk_context *ctx __attribute__((cleanup(destroy_heap))) =
		duk_create_heap_default(); /* may return NULL! */
	check_if(ctx == NULL, ERR_JS_CALL_ALLOC);

	for (size_t i = 0; i < ARRAY_SIZE(d->magic); ++i) {
		const struct string_view *m = d->magic + i;
		debug("eval()-ing magic %zu", i + 1);

		duk_context *guard // NOLINT(clang-analyzer-deadcode.DeadStores)
			__attribute__((cleanup(pop))) = ctx;

		if (duk_peval_lstring(ctx, m->data, m->sz) != 0) {
			return make_result(ERR_JS_CALL_EVAL_MAGIC, peek(ctx));
		}
	}
	debug("eval()-ed %zu magic variables", ARRAY_SIZE(d->magic));

	duk_push_lstring(ctx, d->code.data, d->code.sz);
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
