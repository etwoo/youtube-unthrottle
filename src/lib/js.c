#include "lib/js.h"

#include "lib/re.h"
#include "sys/array.h"
#include "sys/debug.h"

#include <assert.h>
#include <stdbool.h>

/*
 * Some helpful QuickJS references:
 *
 *   https://bellard.org/quickjs/quickjs.html
 */
#include <quickjs.h>

/*
 * Some helpful Jansson references:
 *
 *   https://jansson.readthedocs.io/en/latest/apiref.html
 */
#include <jansson.h>

static void
destroy_runtime(JSRuntime **rt)
{
	if (*rt != NULL) {
		JS_FreeRuntime(*rt);
	}
}

static void
destroy_context(JSContext **ctx)
{
	if (*ctx != NULL) {
		JS_FreeContext(*ctx);
	}
}

struct quickjs_value {
	JSContext *context;
	JSValue val;
};

static void
destroy_value(struct quickjs_value *qval)
{
	if (!JS_IsException(qval->val)) {
		JS_FreeValue(qval->context, qval->val);
	}
}

#define auto_value struct quickjs_value __attribute__((cleanup(destroy_value)))

struct quickjs_str {
	JSContext *context;
	const char *str;
};

static void
destroy_js_str(struct quickjs_str *qstr)
{
	if (qstr->str != NULL) {
		JS_FreeCString(qstr->context, qstr->str);
	}
}

#define auto_js_str struct quickjs_str __attribute__((cleanup(destroy_js_str)))

static void
str_free(char **strp)
{
	free(*strp);
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
	}
	if (!json_is_object(obj)) {
		return make_result(ERR_JS_PARSE_JSON_GET_STREAMINGDATA);
	}

	json_t *streaming_data = json_object_get(obj, "streamingData");
	if (streaming_data == NULL) {
		return make_result(ERR_JS_PARSE_JSON_GET_STREAMINGDATA);
	}
	if (!json_is_object(streaming_data)) {
		return make_result(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS);
	}

	json_t *adaptive_formats =
		json_object_get(streaming_data, "adaptiveFormats");
	if (adaptive_formats == NULL) {
		return make_result(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS);
	}
	if (!json_is_array(adaptive_formats)) {
		return make_result(ERR_JS_PARSE_JSON_ADAPTIVEFORMATS_TYPE);
	}

	values->itag = -1; /* set sentinel value */

	size_t i = 0;
	json_t *cur = NULL;
	json_array_foreach (adaptive_formats, i, cur) {
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
			return make_result(ERR_JS_PARSE_JSON_ELEM_QUALITY);
		}

		const char *q = json_string_value(quality);
		assert(q != NULL);

		auto_result chosen =
			ops->choose_quality
				? ops->choose_quality(q, ops->userdata)
				: RESULT_OK;
		if (chosen.err != OK) {
			debug("Skipping quality: %s", q);
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

	json_t *sabr_url =
		json_object_get(streaming_data, "serverAbrStreamingUrl");
	if (!json_is_string(sabr_url)) {
		return make_result(ERR_JS_SABR_URL_FIND);
	}
	values->sabr_url = strndup(json_string_value(sabr_url),
	                           json_string_length(sabr_url));
	debug("Parsed SABR URI: %s", values->sabr_url);

	json_t *playback_config = /* chain json_object_get() for brevity */
		json_object_get(
			json_object_get(
				json_object_get(
					json_object_get(obj, "playerConfig"),
					"mediaCommonConfig"),
				"mediaUstreamerRequestConfig"),
			"videoPlaybackUstreamerConfig");
	if (!json_is_string(playback_config)) {
		return make_result(ERR_JS_PLAYBACK_CONFIG_FIND);
	}
	values->playback_config = strndup(json_string_value(playback_config),
	                                  json_string_length(playback_config));
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
		return make_result(ERR_JS_MAKE_INNERTUBE_JSON_ID, target_url);
	}
	debug("Parsed ID: %.*s", (int)id.sz, id.data);

	json_auto_t *obj = NULL;
	obj = json_pack("{s{s{ss,ss,ss,ss,si}},ss%,s{ss},s{s{ss,si,sb}},sb,sb}",
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
	                "isInlinePlaybackNoAd",
	                1,
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

	long long int res = strtoll(ts.data, NULL, 0);
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
	d->magic[0].data =
		"var g = {}; document = this; navigator = this; window = this; "
		/* Set fake values for variables accessed by base.js content */
		"document.location = {'hostname': 'foobar'}; "
		"XMLHttpRequest = {'prototype': {'fetch': 'fuzzbuzz'}}; "
		/* Workaround QuickJS's lack of Intl namespace */
		"Intl = {'NumberFormat': {'supportedLocalesOf': "
		"function(x) { return ['en']; }"
		"}}; ";
	d->magic[0].sz = strlen(d->magic[0].data);

	check(re_capture("(?s)var _yt_player={};.function...{.*'use strict';"
	                 "(.*)"
	                 "}.._yt_player.;",
	                 js,
	                 d->magic + 1));
	if (d->magic[1].data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_MAGIC_ONE);
	}
	return RESULT_OK;
}

/*
 * Based on: youtube-dl, yt-dlp, rusty_ytdl
 *
 * find_js_deobfuscator() does the following:
 *
 * 1) find <foo> in base.js like: b=foo[0](b)
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

	struct string_view n1 = {0};
	check(re_capture("[[:alpha:]]=([^\\]]+)\\[0\\]\\([[:alpha:]]\\)",
	                 js,
	                 &n1));
	if (n1.data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_ONE);
	}
	debug("Got function reference: %.*s", (int)n1.sz, n1.data);

	char *p2 __attribute__((cleanup(str_free))) = NULL;
	rc = asprintf(&p2, "\\Q%.*s\\E=\\[([^\\]]+)\\]", (int)n1.sz, n1.data);
	check_if(rc < 0, ERR_JS_DEOBFUSCATOR_ALLOC);

	check(re_capture(p2, js, &d->funcname));
	if (d->funcname.data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_TWO, n1.data, n1.sz);
	}
	debug("Got function name: %.*s", (int)d->funcname.sz, d->funcname.data);

	return RESULT_OK;
}

static WARN_UNUSED result_t
call_js_one(JSContext *ctx,
            JSValue to_call,
            const char *js_arg,
            size_t js_pos,
            const struct call_ops *ops,
            void *userdata)
{
	auto_value global = {ctx, JS_GetGlobalObject(ctx)};
	auto_value arg = {ctx, JS_NewString(ctx, js_arg)};
	auto_value value = {
		ctx,
		JS_Call(ctx, to_call, global.val, 1, &arg.val),
	};

	if (JS_IsException(value.val)) {
		auto_value ex = {ctx, JS_GetException(ctx)};
		auto_js_str str = {ctx, JS_ToCString(ctx, ex.val)};
		return make_result(ERR_JS_CALL_INVOKE, str.str);
	}

	auto_js_str result = {ctx, JS_ToCString(ctx, value.val)};
	if (!JS_IsString(value.val) || result.str == NULL) {
		return make_result(ERR_JS_CALL_GET_RESULT);
	}

	debug("Got JavaScript function result: %s", result.str);
	check(ops->got_result(result.str, js_pos, userdata));

	return RESULT_OK;
}

static WARN_UNUSED result_t
eval_js_magic_one(JSContext *ctx, const struct string_view *magic)
{
	char *deepcopy = strndup(magic->data, magic->sz);
	check_if(deepcopy == NULL, ERR_JS_CALL_ALLOC);
	assert(deepcopy[magic->sz] == '\0');

	auto_value value = {
		ctx,
		JS_Eval(ctx, deepcopy, magic->sz, "m", JS_EVAL_TYPE_GLOBAL),
	};
	free(deepcopy);

	if (JS_IsException(value.val)) {
		auto_value ex = {ctx, JS_GetException(ctx)};
		auto_js_str str = {ctx, JS_ToCString(ctx, ex.val)};
		return make_result(ERR_JS_CALL_EVAL_MAGIC, str.str);
	}
	return RESULT_OK;
}

result_t
call_js_foreach(const struct deobfuscator *d,
                const char *const *args,
                const struct call_ops *ops,
                void *userdata)
{
	JSRuntime *rt __attribute__((cleanup(destroy_runtime))) =
		JS_NewRuntime();
	check_if(rt == NULL, ERR_JS_CALL_ALLOC);

	JSContext *ctx __attribute__((cleanup(destroy_context))) =
		JS_NewContext(rt);
	check_if(ctx == NULL, ERR_JS_CALL_ALLOC);

	for (size_t i = 0; i < ARRAY_SIZE(d->magic); ++i) {
		debug("eval()-ing magic %zu", i + 1);
		check(eval_js_magic_one(ctx, d->magic + i));
	}
	debug("eval()-ed %zu magic variables", ARRAY_SIZE(d->magic));

	char *funcname = strndup(d->funcname.data, d->funcname.sz);
	check_if(funcname == NULL, ERR_JS_CALL_ALLOC);

	auto_value global = {ctx, JS_GetGlobalObject(ctx)};
	auto_value to_call = {
		ctx,
		JS_GetPropertyStr(ctx, global.val, funcname),
	};
	free(funcname);

	if (!JS_IsFunction(ctx, to_call.val)) {
		return make_result(ERR_JS_CALL_LOOKUP, "did not find function");
	}

	for (size_t i = 0; args[i]; ++i) {
		check(call_js_one(ctx, to_call.val, args[i], i, ops, userdata));
	}

	return RESULT_OK;
}

#undef auto_value
#undef auto_js_str
