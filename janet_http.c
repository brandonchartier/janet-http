#include <janet.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

/* --- Dynamic buffer for accumulating response data --- */

typedef struct {
    char *data;
    size_t len;
} Buf;

static size_t buf_append(char *ptr, size_t size, size_t nmemb, void *ud) {
    Buf *buf = (Buf *)ud;
    size_t n = size * nmemb;
    char *tmp = realloc(buf->data, buf->len + n + 1);
    if (!tmp) return 0;
    buf->data = tmp;
    memcpy(buf->data + buf->len, ptr, n);
    buf->len += n;
    buf->data[buf->len] = '\0';
    return n;
}

/* --- Request state passed between main thread and worker --- */

typedef struct {
    char *url;
    char *method;
    char *body;
    size_t body_len;
    int follow_redirects;
    long max_redirects;
    char *user_agent;
    char *username;
    char *password;
    int keep_alive;
    struct curl_slist *req_headers;
    long status;
    Buf body_buf;
    Buf headers_buf;
    char error[CURL_ERROR_SIZE];
    JanetFiber *fiber;
} Req;

static void req_free(Req *r) {
    free(r->url);
    free(r->method);
    free(r->body);
    free(r->user_agent);
    free(r->username);
    free(r->password);
    free(r->body_buf.data);
    free(r->headers_buf.data);
    curl_slist_free_all(r->req_headers);
    free(r);
}

static Req *req_build(const char *method, const char *url, Janet opts) {
    if (!janet_checktype(opts, JANET_NIL) &&
        !janet_checktype(opts, JANET_TABLE) &&
        !janet_checktype(opts, JANET_STRUCT))
        janet_panicf("expected table or struct for options, got %t", opts);

    Req *r = calloc(1, sizeof(Req));
    r->url = strdup(url);
    r->method = strdup(method);
    r->follow_redirects = 1;
    r->max_redirects = 50;
    r->user_agent = strdup("janet http client");
    r->keep_alive = 1;

    if (janet_checktype(opts, JANET_NIL))
        return r;

    Janet v;
    const uint8_t *bytes;
    int32_t blen;
    const Janet *items;
    int32_t items_len;

    v = janet_get(opts, janet_ckeywordv("body"));
    if (janet_bytes_view(v, &bytes, &blen)) {
        r->body = malloc(blen + 1);
        memcpy(r->body, bytes, blen);
        r->body[blen] = '\0';
        r->body_len = (size_t)blen;
    }

    v = janet_get(opts, janet_ckeywordv("follow-redirects"));
    if (!janet_checktype(v, JANET_NIL))
        r->follow_redirects = janet_truthy(v);

    v = janet_get(opts, janet_ckeywordv("max-redirects"));
    if (janet_checktype(v, JANET_NUMBER))
        r->max_redirects = (long)janet_unwrap_number(v);

    v = janet_get(opts, janet_ckeywordv("user-agent"));
    if (janet_bytes_view(v, &bytes, &blen)) {
        free(r->user_agent);
        r->user_agent = malloc(blen + 1);
        memcpy(r->user_agent, bytes, blen);
        r->user_agent[blen] = '\0';
    }

    v = janet_get(opts, janet_ckeywordv("keep-alive"));
    if (!janet_checktype(v, JANET_NIL))
        r->keep_alive = janet_truthy(v);

    v = janet_get(opts, janet_ckeywordv("username"));
    if (janet_bytes_view(v, &bytes, &blen)) {
        r->username = malloc(blen + 1);
        memcpy(r->username, bytes, blen);
        r->username[blen] = '\0';
    }

    v = janet_get(opts, janet_ckeywordv("password"));
    if (janet_bytes_view(v, &bytes, &blen)) {
        r->password = malloc(blen + 1);
        memcpy(r->password, bytes, blen);
        r->password[blen] = '\0';
    }

    v = janet_get(opts, janet_ckeywordv("headers"));
    if (janet_indexed_view(v, &items, &items_len)) {
        struct curl_slist *list = NULL;
        for (int32_t i = 0; i < items_len; i++) {
            const uint8_t *hdr;
            int32_t hdr_len;
            if (janet_bytes_view(items[i], &hdr, &hdr_len))
                list = curl_slist_append(list, (const char *)hdr);
        }
        r->req_headers = list;
    }

    return r;
}

/* --- Background worker: no Janet API calls permitted --- */

static JanetEVGenericMessage do_request(JanetEVGenericMessage msg) {
    Req *r = (Req *)msg.argp;

    CURL *curl = curl_easy_init();
    if (!curl) {
        snprintf(r->error, CURL_ERROR_SIZE, "curl_easy_init failed");
        return msg;
    }

    curl_easy_setopt(curl, CURLOPT_URL, r->url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, r->method);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, r->error);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, buf_append);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r->body_buf);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, buf_append);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &r->headers_buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, (long)r->follow_redirects);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, r->max_redirects);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, r->user_agent);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, (long)r->keep_alive);

    if (r->username) curl_easy_setopt(curl, CURLOPT_USERNAME, r->username);
    if (r->password) curl_easy_setopt(curl, CURLOPT_PASSWORD, r->password);
    if (r->req_headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, r->req_headers);

    if (strcmp(r->method, "HEAD") == 0)
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    if (r->body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, r->body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)r->body_len);
    }

    CURLcode res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &r->status);
    else if (!r->error[0])
        strncpy(r->error, curl_easy_strerror(res), CURL_ERROR_SIZE - 1);

    curl_easy_cleanup(curl);
    return msg;
}

/* --- Header parsing --- */

/* curl delivers raw HTTP headers: status line, then "Key: Value\r\n" lines,
 * ending with a blank line. Parse into a Janet struct with lowercased keys. */
static Janet parse_headers(const char *raw, size_t len) {
    const char *p = raw;
    const char *end = raw + len;

    while (p < end && *p != '\n') p++;
    if (p < end) p++;

    int count = 0;
    const char *scan = p;
    while (scan < end) {
        const char *nl = memchr(scan, '\n', end - scan);
        if (!nl) break;
        size_t line_len = nl - scan;
        if (line_len > 0 && scan[line_len - 1] == '\r') line_len--;
        if (line_len > 0 && memchr(scan, ':', line_len)) count++;
        scan = nl + 1;
    }

    JanetKV *st = janet_struct_begin(count);
    scan = p;
    while (scan < end) {
        const char *nl = memchr(scan, '\n', end - scan);
        if (!nl) break;
        size_t line_len = nl - scan;
        if (line_len > 0 && scan[line_len - 1] == '\r') line_len--;
        if (line_len == 0) { scan = nl + 1; break; }

        const char *colon = memchr(scan, ':', line_len);
        if (colon) {
            size_t klen = colon - scan;
            const char *vstart = colon + 1;
            size_t vlen = line_len - klen - 1;
            while (vlen > 0 && *vstart == ' ') { vstart++; vlen--; }

            char *kbuf = malloc(klen);
            for (size_t i = 0; i < klen; i++)
                kbuf[i] = (char)(scan[i] >= 'A' && scan[i] <= 'Z' ? scan[i] + 32 : scan[i]);
            janet_struct_put(st,
                janet_wrap_string(janet_string((const uint8_t *)kbuf, (int32_t)klen)),
                janet_wrap_string(janet_string((const uint8_t *)vstart, (int32_t)vlen)));
            free(kbuf);
        }
        scan = nl + 1;
    }
    return janet_wrap_struct(janet_struct_end(st));
}

/* --- Main-thread completion callback --- */

static void on_complete(JanetEVGenericMessage msg) {
    Req *r = (Req *)msg.argp;
    JanetFiber *fiber = r->fiber;

    if (!janet_fiber_can_resume(fiber)) {
        janet_gcunroot(janet_wrap_fiber(fiber));
        req_free(r);
        return;
    }

    if (r->error[0]) {
        janet_cancel(fiber, janet_cstringv(r->error));
    } else {
        JanetTable *t = janet_table(3);
        janet_table_put(t, janet_ckeywordv("status"),
            janet_wrap_integer((int32_t)r->status));
        janet_table_put(t, janet_ckeywordv("body"),
            janet_wrap_string(janet_string(
                (const uint8_t *)(r->body_buf.data ? r->body_buf.data : ""),
                (int32_t)r->body_buf.len)));
        janet_table_put(t, janet_ckeywordv("headers"),
            r->headers_buf.data
                ? parse_headers(r->headers_buf.data, r->headers_buf.len)
                : janet_wrap_struct(janet_struct_end(janet_struct_begin(0))));
        janet_schedule(fiber, janet_wrap_table(t));
    }

    janet_gcunroot(janet_wrap_fiber(fiber));
    req_free(r);
}

/* --- Request dispatch --- */

static JANET_NO_RETURN void start_request(Req *r) {
    r->fiber = janet_root_fiber();
    janet_gcroot(janet_wrap_fiber(r->fiber));
    JanetEVGenericMessage msg = {0};
    msg.argp = r;
    janet_ev_threaded_call(do_request, msg, on_complete);
    janet_await();
}

static JANET_NO_RETURN void dispatch(const char *method, int32_t argc, Janet *argv) {
    start_request(req_build(method,
        (const char *)janet_getstring(argv, 0),
        argc > 1 ? argv[1] : janet_wrap_nil()));
}

/* --- Janet C functions --- */

static Janet cfun_request(int32_t argc, Janet *argv) {
    janet_arity(argc, 2, 3);
    start_request(req_build(
        (const char *)janet_getstring(argv, 0),
        (const char *)janet_getstring(argv, 1),
        argc > 2 ? argv[2] : janet_wrap_nil()));
}

static Janet cfun_get(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("GET", argc, argv);
}

static Janet cfun_post(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("POST", argc, argv);
}

static Janet cfun_put(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("PUT", argc, argv);
}

static Janet cfun_patch(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("PATCH", argc, argv);
}

static Janet cfun_delete(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("DELETE", argc, argv);
}

static Janet cfun_head(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("HEAD", argc, argv);
}

static Janet cfun_options(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("OPTIONS", argc, argv);
}

static Janet cfun_trace(int32_t argc, Janet *argv) {
    janet_arity(argc, 1, 2);
    dispatch("TRACE", argc, argv);
}

static Janet cfun_url_encode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    const uint8_t *s;
    int32_t len;
    if (!janet_bytes_view(argv[0], &s, &len))
        janet_panicf("expected string or buffer, got %t", argv[0]);
    char *encoded = curl_easy_escape(NULL, (const char *)s, (int)len);
    if (!encoded) janet_panic("curl_easy_escape failed");
    Janet result = janet_cstringv(encoded);
    curl_free(encoded);
    return result;
}

static Janet cfun_form_encode(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);
    const JanetKV *kvs;
    int32_t len, cap;
    if (!janet_dictionary_view(argv[0], &kvs, &len, &cap))
        janet_panicf("expected table or struct, got %t", argv[0]);

    JanetBuffer *buf = janet_buffer(64);
    int first = 1;
    for (int32_t i = 0; i < cap; i++) {
        if (janet_checktype(kvs[i].key, JANET_NIL)) continue;
        JanetString ks = janet_to_string(kvs[i].key);
        JanetString vs = janet_to_string(kvs[i].value);
        char *ek = curl_easy_escape(NULL, (const char *)ks, janet_string_length(ks));
        char *ev = curl_easy_escape(NULL, (const char *)vs, janet_string_length(vs));
        if (!first) janet_buffer_push_u8(buf, '&');
        janet_buffer_push_cstring(buf, ek);
        janet_buffer_push_u8(buf, '=');
        janet_buffer_push_cstring(buf, ev);
        curl_free(ek);
        curl_free(ev);
        first = 0;
    }
    return janet_wrap_string(janet_string(buf->data, buf->count));
}

static const JanetReg cfuns[] = {
    {"request", cfun_request,
     "(http/request method url &opt options)\n\n"
     "Perform an arbitrary HTTP request. method is a string (\"GET\", \"POST\", etc.).\n"
     "options is an optional table or struct:\n"
     "  :body            string or buffer - request body\n"
     "  :headers         array of \"Key: Value\" strings\n"
     "  :follow-redirects  boolean (default true)\n"
     "  :max-redirects   integer (default 50)\n"
     "  :user-agent      string (default \"janet http client\")\n"
     "  :keep-alive      boolean (default true)\n"
     "  :username        string - basic auth\n"
     "  :password        string - basic auth\n"
     "Returns @{:status n :body string :headers struct}."},
    {"get",     cfun_get,     "(http/get url &opt options)\n\nGET url."},
    {"post",    cfun_post,    "(http/post url &opt options)\n\nPOST to url. Pass :body in options."},
    {"put",     cfun_put,     "(http/put url &opt options)\n\nPUT to url. Pass :body in options."},
    {"patch",   cfun_patch,   "(http/patch url &opt options)\n\nPATCH url. Pass :body in options."},
    {"delete",  cfun_delete,  "(http/delete url &opt options)\n\nDELETE url."},
    {"head",    cfun_head,    "(http/head url &opt options)\n\nHEAD url."},
    {"options", cfun_options, "(http/options url &opt options)\n\nOPTIONS url."},
    {"trace",   cfun_trace,   "(http/trace url &opt options)\n\nTRACE url."},
    {"url-encode", cfun_url_encode,
     "(http/url-encode s)\n\nPercent-encode a string for use in a URL."},
    {"form-encode", cfun_form_encode,
     "(http/form-encode dict)\n\n"
     "Encode a table or struct as application/x-www-form-urlencoded.\n"
     "Keys and values are coerced to strings and percent-encoded."},
    {NULL, NULL, NULL}
};

JANET_MODULE_ENTRY(JanetTable *env) {
    curl_global_init(CURL_GLOBAL_ALL);
    janet_cfuns(env, "http", cfuns);
}
