#include "lib/js.h"

#include "lib/re.h"
#include "sys/array.h"
#include "sys/debug.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

/*
 * Some helpful QuickJS references:
 *
 *   https://bellard.org/quickjs/quickjs.html
 */
#include <quickjs.h>

static void
qjs_runtime_cleanup(JSRuntime **rt)
{
	if (*rt != NULL) {
		JS_FreeRuntime(*rt);
	}
}

#define auto_runtime JSRuntime __attribute__((cleanup(qjs_runtime_cleanup)))

static void
qjs_context_cleanup(JSContext **ctx)
{
	if (*ctx != NULL) {
		JS_FreeContext(*ctx);
	}
}

#define auto_context JSContext __attribute__((cleanup(qjs_context_cleanup)))

struct qjs_str {
	JSContext *context;
	const char *str;
};

static void
qjs_str_cleanup(struct qjs_str *qstr)
{
	if (qstr->str != NULL) {
		JS_FreeCString(qstr->context, qstr->str);
	}
}

#define auto_js_str struct qjs_str __attribute__((cleanup(qjs_str_cleanup)))

struct qjs_value {
	JSContext *context;
	JSValue val;
};

static void
qjs_value_cleanup(struct qjs_value *qval)
{
	JS_FreeValue(qval->context, qval->val);
}

#define auto_value struct qjs_value __attribute__((cleanup(qjs_value_cleanup)))

static WARN_UNUSED bool
is_exception(struct qjs_value qval)
{
	return JS_IsException(qval.val);
}

static WARN_UNUSED bool
is_undefined(struct qjs_value qval)
{
	return JS_IsUndefined(qval.val);
}

static WARN_UNUSED bool
is_object(struct qjs_value qval)
{
	return JS_IsObject(qval.val);
}

static WARN_UNUSED bool
is_array(struct qjs_value qval)
{
	return JS_IsArray(qval.context, qval.val);
}

static WARN_UNUSED bool
is_string(struct qjs_value qval)
{
	return JS_IsString(qval.val);
}

static WARN_UNUSED bool
is_number(struct qjs_value qval)
{
	return JS_IsNumber(qval.val);
}

static WARN_UNUSED struct qjs_value
get(struct qjs_value qval, const char *name)
{
	return (struct qjs_value){
		.context = qval.context,
		.val = JS_GetPropertyStr(qval.context, qval.val, name),
	};
}

static WARN_UNUSED struct qjs_value
get_free(struct qjs_value use_then_free, const char *name)
{
	struct qjs_value result = get(use_then_free, name);
	JS_FreeValue(use_then_free.context, use_then_free.val);
	return result;
}

static WARN_UNUSED struct qjs_str
to_cstring(struct qjs_value qval)
{
	return (struct qjs_str){
		.context = qval.context,
		.str = JS_ToCString(qval.context, qval.val),
	};
}

#define check_exception_message(qval, err_type)                                \
	do {                                                                   \
		if (is_exception(qval)) {                                      \
			auto_value ex = {                                      \
				(qval).context,                                \
				JS_GetException((qval).context),               \
			};                                                     \
			auto_js_str str = to_cstring(ex);                      \
			return make_result(err_type, str.str);                 \
		}                                                              \
	} while (0)

struct qjs_atom {
	JSContext *context;
	JSAtom atom;
};

static void
qjs_atom_cleanup(struct qjs_atom *qatom)
{
	JS_FreeAtom(qatom->context, qatom->atom);
}

#define auto_atom struct qjs_atom __attribute__((cleanup(qjs_atom_cleanup)))

static const char MTVIDEO[] = "video/";
static const int32_t ITAG_SENTINEL = -1;

static WARN_UNUSED result_t
parse_json_candidate(JSContext *ctx,
                     struct qjs_value candidate,
                     const struct parse_ops *ops,
                     long long int *out)
{
	if (!is_object(candidate)) {
		return make_result(ERR_JS_PARSE_JSON_ELEM_TYPE);
	}

	auto_value mimetype_json = get(candidate, "mimeType");
	if (!is_string(mimetype_json)) {
		return make_result(ERR_JS_PARSE_JSON_ELEM_MIMETYPE);
	}

	auto_js_str mimetype = to_cstring(mimetype_json);
	assert(mimetype.str != NULL);

	if (0 != strncmp(mimetype.str, MTVIDEO, strlen(MTVIDEO))) {
		debug("Skipping mimeType: %s", mimetype.str);
		return RESULT_OK;
	}

	auto_value qlabel_json = get(candidate, "qualityLabel");
	if (!is_string(qlabel_json)) {
		return make_result(ERR_JS_PARSE_JSON_ELEM_QUALITY);
	}

	auto_js_str qlabel = to_cstring(qlabel_json);
	assert(qlabel.str != NULL);

	auto_result chosen =
		ops->choose_quality
			? ops->choose_quality(qlabel.str, ops->userdata)
			: RESULT_OK;
	if (chosen.err != OK) {
		debug("Skipping qualityLabel: %s", qlabel.str);
		return RESULT_OK;
	}

	auto_value itag = get(candidate, "itag");
	int32_t tmp = ITAG_SENTINEL;
	if (!is_number(itag) || JS_ToInt32(ctx, &tmp, itag.val) < 0) {
		return make_result(ERR_JS_PARSE_JSON_ELEM_ITAG);
	}
	assert(tmp != ITAG_SENTINEL);

	*out = tmp;
	return RESULT_OK;
}

result_t
parse_json(const struct string_view *json,
           const struct parse_ops *ops,
           struct parse_values *values)
{
	// debug("Got JSON blob: %.*s", json->sz, json->data);
	debug("Got JSON blob of size %zu", json->sz);

	auto_runtime *rt = JS_NewRuntime();
	check_if(rt == NULL, ERR_JS_CALL_ALLOC);

	auto_context *ctx = JS_NewContext(rt);
	check_if(ctx == NULL, ERR_JS_CALL_ALLOC);

	auto_value obj = {
		ctx,
		JS_ParseJSON(ctx, json->data, json->sz, "JSON"),
	};
	check_exception_message(obj, ERR_JS_PARSE_JSON_DECODE);
	if (!is_object(obj)) {
		return make_result(ERR_JS_PARSE_JSON_GET_STREAMINGDATA);
	}

	auto_value streaming_data = get(obj, "streamingData");
	if (!is_object(streaming_data)) {
		return make_result(ERR_JS_PARSE_JSON_GET_STREAMINGDATA);
	}

	auto_value adaptive_formats = get(streaming_data, "adaptiveFormats");
	if (!is_array(adaptive_formats)) {
		return make_result(ERR_JS_PARSE_JSON_GET_ADAPTIVEFORMATS);
	}

	values->itag = ITAG_SENTINEL;

	for (size_t i = 0; values->itag == ITAG_SENTINEL; ++i) {
		auto_value cur = {
			ctx,
			JS_GetPropertyUint32(ctx, adaptive_formats.val, i),
		};
		if (is_undefined(cur)) {
			/* iterated past final array element */
			return make_result(ERR_JS_PARSE_JSON_NO_MATCH);
		}
		check(parse_json_candidate(ctx, cur, ops, &values->itag));
	}

	debug("Parsed itag=%lld", values->itag);

	auto_value sabr_url = get(streaming_data, "serverAbrStreamingUrl");
	if (is_string(sabr_url)) {
		auto_js_str str = to_cstring(sabr_url);
		values->sabr_url = strdup(str.str);
	} else {
		return make_result(ERR_JS_SABR_URL_FIND);
	}
	debug("Parsed SABR URI: %s", values->sabr_url);

	auto_value playback_config =
		get_free(get_free(get_free(get(obj, "playerConfig"),
	                                   "mediaCommonConfig"),
	                          "mediaUstreamerRequestConfig"),
	                 "videoPlaybackUstreamerConfig");
	if (is_string(playback_config)) {
		auto_js_str str = to_cstring(playback_config);
		values->playback_config = strdup(str.str);
	} else {
		return make_result(ERR_JS_PLAYBACK_CONFIG_FIND);
	}
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

/* clang-format off */
static const char INNERTUBE_POST_FMT[] =
	"{"
		"\"context\":{"
			"\"client\":{"
				"\"clientName\":\"WEB\","
				"\"clientVersion\":\"2.20240726.00.00\","
				"\"hl\":\"en\","
				"\"timeZone\":\"UTC\","
				"\"utcOffsetMinutes\":0"
			"}"
		"},"
		"\"videoId\":\"%.*s\","
		"\"serviceIntegrityDimensions\":{"
			"\"poToken\":\"%s\""
		"},"
		"\"playbackContext\":{"
			"\"contentPlaybackContext\":{"
				"\"html5Preference\":\"HTML5_PREF_WANTS\","
				"\"signatureTimestamp\":%lld,"
				"\"isInlinePlaybackNoAd\":true"
			"}"
		"},"
		"\"contentCheckOk\":true,"
		"\"racyCheckOk\":true"
	"}";
/* clang-format on */

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

	const int rc = asprintf(body,
	                        INNERTUBE_POST_FMT,
	                        (int)id.sz,
	                        id.data,
	                        proof_of_origin,
	                        timestamp);
	check_if(rc < 0, ERR_JS_MAKE_INNERTUBE_JSON_ALLOC);

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
		"g = {}; document = this; navigator = this; window = this; "
		/* Set fake values for variables accessed by base.js content */
		"document.location = {'hostname': 'foobar'}; "
		"XMLHttpRequest = class {}; "
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

result_t
find_js_deobfuscator(const struct string_view *js, struct deobfuscator *d)
{
	check(re_capture("\\(new ([^\\(]+)\\(.,!0\\)\\)\\.get\\(\"n\"\\);",
	                 js,
	                 &d->funcname));
	if (d->funcname.data == NULL) {
		return make_result(ERR_JS_DEOB_FIND_FUNC_ONE);
	}
	debug("Got function name: %.*s", (int)d->funcname.sz, d->funcname.data);
	return RESULT_OK;
}

static WARN_UNUSED result_t
eval_js(const struct string_view *js, unsigned err_type, struct qjs_value *out)
{
	/*
	 * QuickJS's JS_Eval() API requires NUL-terminated input, even
	 * when given an explicit size parameter. Make a temporary,
	 * NUL-terminated copy of each JS fragment accordingly.
	 */
	char *s = strndup(js->data, js->sz);
	check_if(s == NULL, ERR_JS_CALL_ALLOC);

	out->val = JS_Eval(out->context, s, js->sz, "JS", JS_EVAL_TYPE_GLOBAL);
	free(s);

	check_exception_message(*out, err_type);
	return RESULT_OK;
}

static WARN_UNUSED result_t
call_js_one(struct qjs_value proto,
            const char *js_arg,
            size_t js_pos,
            const struct call_ops *ops,
            void *userdata)
{
	JSContext *ctx = proto.context;

	auto_value obj = {ctx, JS_UNDEFINED};
	{
		auto_value arg0 = {ctx, JS_NewString(ctx, js_arg)};
		check_if(is_exception(arg0), ERR_JS_CALL_ALLOC);

		auto_value arg1 = {ctx, JS_NewBool(ctx, !0)};
		check_if(is_exception(arg1), ERR_JS_CALL_ALLOC);

		JSValueConst a[2] = {
			arg0.val,
			arg1.val,
		};
		obj.val = JS_CallConstructor(ctx, proto.val, ARRAY_SIZE(a), a);
		check_exception_message(obj, ERR_JS_CALL_CONSTRUCTOR);
	}

	auto_value val = {ctx, JS_UNDEFINED};
	{
		auto_atom method = {ctx, JS_NewAtom(ctx, "get")};
		check_if(method.atom == JS_ATOM_NULL, ERR_JS_CALL_ALLOC);

		auto_value arg_n = {ctx, JS_NewString(ctx, "n")};
		check_if(is_exception(arg_n), ERR_JS_CALL_ALLOC);

		val.val = JS_Invoke(ctx, obj.val, method.atom, 1, &arg_n.val);
		check_exception_message(val, ERR_JS_CALL_INVOKE);
	}

	auto_js_str result = to_cstring(val);
	if (!is_string(val) || result.str == NULL) {
		return make_result(ERR_JS_CALL_GET_RESULT);
	}

	debug("Got JavaScript function result: %s", result.str);
	check(ops->got_result(result.str, js_pos, userdata));
	return RESULT_OK;
}

result_t
call_js_foreach(const struct deobfuscator *d,
                const char *const *args,
                const struct call_ops *ops,
                void *userdata)
{
	auto_runtime *rt = JS_NewRuntime();
	check_if(rt == NULL, ERR_JS_CALL_ALLOC);

	auto_context *ctx = JS_NewContext(rt);
	check_if(ctx == NULL, ERR_JS_CALL_ALLOC);

	for (size_t i = 0; i < ARRAY_SIZE(d->magic); ++i) {
		debug("eval()-ing magic %zu", i + 1);
		auto_value tmp = {ctx, JS_UNDEFINED};
		check(eval_js(&d->magic[i], ERR_JS_CALL_EVAL_MAGIC, &tmp));
	}
	debug("eval()-ed %zu magic variables", ARRAY_SIZE(d->magic));

	debug("eval()-ing expr: %.*s", (int)d->funcname.sz, d->funcname.data);
	auto_value prototype = {ctx, JS_UNDEFINED};
	check(eval_js(&d->funcname, ERR_JS_CALL_LOOKUP, &prototype));

	if (!is_object(prototype)) {
		return make_result(ERR_JS_CALL_LOOKUP, "did not find class");
	}

	for (size_t i = 0; args[i]; ++i) {
		debug("Calling function with argument: %s", args[i]);
		check(call_js_one(prototype, args[i], i, ops, userdata));
	}

	return RESULT_OK;
}

#undef auto_runtime
#undef auto_context
#undef auto_js_str
#undef auto_value
#undef check_exception_message
#undef auto_atom
