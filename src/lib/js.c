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
#ifdef WITH_DEBUG_OUTPUT
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
find_sabr_url(const struct string_view *html, struct string_view *sabr)
{
	check(re_capture("\"serverAbrStreamingUrl\":\"([^\"]+)\"", html, sabr));
	if (sabr->data == NULL) {
		return make_result(ERR_JS_SABR_URL_FIND);
	}

	debug("Parsed SABR URI: %.*s", (int)sabr->sz, sabr->data);
	return RESULT_OK;
}

result_t
find_playback_config(const struct string_view *html, struct string_view *config)
{
	check(re_capture("\"videoPlaybackUstreamerConfig\":\"([^\"]+)\"",
	                 html,
	                 config));
	if (config->data == NULL) {
		return make_result(ERR_JS_PLAYBACK_CONFIG_FIND);
	}

	debug("Parsed playback config: %.*s", (int)config->sz, config->data);
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
