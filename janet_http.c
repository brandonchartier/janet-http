#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <janet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

typedef struct {
  char *data;
  size_t len;
  size_t max; /* cap on accumulated bytes; 0 means unlimited */
} Buf;

static size_t buf_append(char *ptr, size_t size, size_t nmemb, void *ud) {
  Buf *buf = (Buf *)ud;
  size_t n = size * nmemb;
  /* Returning a short count aborts the transfer (curl reports CURLE_WRITE_ERROR).
     This bounds memory against a server that streams an unbounded response. */
  if (buf->max && buf->len + n > buf->max)
    return 0;
  char *tmp = realloc(buf->data, buf->len + n + 1);
  if (!tmp)
    return 0;
  buf->data = tmp;
  memcpy(buf->data + buf->len, ptr, n);
  buf->len += n;
  buf->data[buf->len] = '\0';
  return n;
}

typedef struct {
  CURL *easy;
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
  size_t max_response_size;
  struct curl_slist *req_headers;
  long status;
  Buf body_buf;
  Buf headers_buf;
  char error[CURL_ERROR_SIZE];
  JanetFiber *fiber;
} ReqHandle;

static void rh_free(ReqHandle *rh) {
  if (rh->easy)
    curl_easy_cleanup(rh->easy);
  free(rh->url);
  free(rh->method);
  free(rh->body);
  free(rh->user_agent);
  free(rh->username);
  free(rh->password);
  free(rh->body_buf.data);
  free(rh->headers_buf.data);
  curl_slist_free_all(rh->req_headers);
  free(rh);
}

typedef struct {
  CURLM *multi;
  int epoll_fd;
  int wakeup_pipe[2];
  pthread_t thread;
  pthread_mutex_t lock;
  JanetVM *vm;
  volatile int running;
} MultiState;

static MultiState g_ms;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void on_complete(JanetEVGenericMessage msg);
static void *curl_thread(void *arg);
static Janet parse_headers(const char *raw, size_t len);

/* socket_cb and timer_cb are invoked by curl from inside curl_multi_* calls,
   always with g_ms.lock already held. */
static int socket_cb(CURL *easy, curl_socket_t s, int what, void *userp,
                     void *socketp) {
  (void)easy;
  MultiState *ms = (MultiState *)userp;

  if (what == CURL_POLL_REMOVE) {
    epoll_ctl(ms->epoll_fd, EPOLL_CTL_DEL, (int)s, NULL);
  } else {
    struct epoll_event ev = {0};
    if (what == CURL_POLL_IN)
      ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    else if (what == CURL_POLL_OUT)
      ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
    else
      ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP;
    ev.data.fd = (int)s;
    int op = socketp ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    epoll_ctl(ms->epoll_fd, op, (int)s, &ev);
    curl_multi_assign(ms->multi, s, (void *)1);
  }
  return 0;
}

/* Nudge the curl thread to re-evaluate its handles. Fire-and-forget: the pipe
   is non-blocking, so a full pipe (a wakeup already pending) just yields EAGAIN
   and the thread also polls at least once a second as a backstop. */
static void wake_curl_thread(int fd) {
  char byte = 0;
  ssize_t w = write(fd, &byte, 1);
  (void)w;
}

static int timer_cb(CURLM *multi, long timeout_ms, void *userp) {
  (void)multi;
  (void)timeout_ms;
  MultiState *ms = (MultiState *)userp;
  wake_curl_thread(ms->wakeup_pipe[1]);
  return 0;
}

#define MAX_EPOLL_EVENTS 64

static void check_completions(MultiState *ms) {
  int msgs_left;
  CURLMsg *msg;
  while ((msg = curl_multi_info_read(ms->multi, &msgs_left))) {
    if (msg->msg != CURLMSG_DONE)
      continue;

    ReqHandle *rh = NULL;
    curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &rh);

    if (msg->data.result == CURLE_OK)
      curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &rh->status);
    else if (!rh->error[0])
      strncpy(rh->error, curl_easy_strerror(msg->data.result),
              CURL_ERROR_SIZE - 1);

    curl_multi_remove_handle(ms->multi, msg->easy_handle);
    curl_easy_cleanup(msg->easy_handle);
    rh->easy = NULL;

    JanetEVGenericMessage ev_msg = {0};
    ev_msg.argp = rh;
    janet_ev_post_event(ms->vm, on_complete, ev_msg);
  }
}

static void handle_socket_events(MultiState *ms, struct epoll_event *events,
                                 int n) {
  for (int i = 0; i < n; i++) {
    int fd = events[i].data.fd;
    if (fd == ms->wakeup_pipe[0]) {
      char buf[64];
      while (read(fd, buf, sizeof(buf)) > 0)
        ;
      /* Drive curl to pick up any newly added handles. */
      int still_running;
      curl_multi_socket_action(ms->multi, CURL_SOCKET_TIMEOUT, 0,
                               &still_running);
      continue;
    }
    int ev_bitmask = 0;
    if (events[i].events & (EPOLLIN | EPOLLHUP))
      ev_bitmask |= CURL_CSELECT_IN;
    if (events[i].events & EPOLLOUT)
      ev_bitmask |= CURL_CSELECT_OUT;
    if (events[i].events & EPOLLERR)
      ev_bitmask |= CURL_CSELECT_ERR;
    int still_running;
    curl_multi_socket_action(ms->multi, fd, ev_bitmask, &still_running);
  }
}

static void *curl_thread(void *arg) {
  MultiState *ms = (MultiState *)arg;
  struct epoll_event events[MAX_EPOLL_EVENTS];

  while (ms->running) {
    long timeout_ms = -1;
    pthread_mutex_lock(&ms->lock);
    curl_multi_timeout(ms->multi, &timeout_ms);
    pthread_mutex_unlock(&ms->lock);

    int wait_ms =
        (timeout_ms < 0 || timeout_ms > 1000) ? 1000 : (int)timeout_ms;
    int n = epoll_wait(ms->epoll_fd, events, MAX_EPOLL_EVENTS, wait_ms);
    if (n < 0 && errno == EINTR)
      continue;

    pthread_mutex_lock(&ms->lock);
    if (n == 0) {
      int still_running;
      curl_multi_socket_action(ms->multi, CURL_SOCKET_TIMEOUT, 0,
                               &still_running);
    } else {
      handle_socket_events(ms, events, n);
    }
    check_completions(ms);
    pthread_mutex_unlock(&ms->lock);
  }
  return NULL;
}

static void multi_init(void) {
  g_ms.vm = janet_local_vm();
  g_ms.multi = curl_multi_init();

  g_ms.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (g_ms.epoll_fd < 0)
    janet_panic("epoll_create1 failed");

  if (pipe(g_ms.wakeup_pipe) < 0)
    janet_panic("pipe failed");
  fcntl(g_ms.wakeup_pipe[0], F_SETFL, O_NONBLOCK);
  fcntl(g_ms.wakeup_pipe[1], F_SETFL, O_NONBLOCK);

  struct epoll_event ev = {.events = EPOLLIN, .data.fd = g_ms.wakeup_pipe[0]};
  epoll_ctl(g_ms.epoll_fd, EPOLL_CTL_ADD, g_ms.wakeup_pipe[0], &ev);

  curl_multi_setopt(g_ms.multi, CURLMOPT_SOCKETFUNCTION, socket_cb);
  curl_multi_setopt(g_ms.multi, CURLMOPT_SOCKETDATA, &g_ms);
  curl_multi_setopt(g_ms.multi, CURLMOPT_TIMERFUNCTION, timer_cb);
  curl_multi_setopt(g_ms.multi, CURLMOPT_TIMERDATA, &g_ms);

  pthread_mutex_init(&g_ms.lock, NULL);
  g_ms.running = 1;
  pthread_create(&g_ms.thread, NULL, curl_thread, &g_ms);
}

/* Runs on the Janet thread, posted by the curl thread via janet_ev_post_event,
   so it is safe to build and schedule Janet values here. */
static void on_complete(JanetEVGenericMessage msg) {
  ReqHandle *rh = (ReqHandle *)msg.argp;
  JanetFiber *fiber = rh->fiber;

  janet_ev_dec_refcount();

  if (!janet_fiber_can_resume(fiber)) {
    janet_gcunroot(janet_wrap_fiber(fiber));
    rh_free(rh);
    return;
  }

  if (rh->error[0]) {
    janet_cancel(fiber, janet_cstringv(rh->error));
  } else {
    JanetTable *t = janet_table(3);
    janet_table_put(t, janet_ckeywordv("status"),
                    janet_wrap_integer((int32_t)rh->status));
    janet_table_put(
        t, janet_ckeywordv("body"),
        janet_wrap_string(janet_string(
            (const uint8_t *)(rh->body_buf.data ? rh->body_buf.data : ""),
            (int32_t)rh->body_buf.len)));
    janet_table_put(
        t, janet_ckeywordv("headers"),
        rh->headers_buf.data
            ? parse_headers(rh->headers_buf.data, rh->headers_buf.len)
            : janet_wrap_struct(janet_struct_end(janet_struct_begin(0))));
    janet_schedule(fiber, janet_wrap_table(t));
  }

  janet_gcunroot(janet_wrap_fiber(fiber));
  rh_free(rh);
}

/* Length of the line at scan, excluding any trailing CRLF/LF, and advance
   *next past the newline (or to end for the final line). */
static size_t next_line(const char *scan, const char *end, const char **next) {
  const char *nl = memchr(scan, '\n', end - scan);
  size_t len = nl ? (size_t)(nl - scan) : (size_t)(end - scan);
  if (len > 0 && scan[len - 1] == '\r')
    len--;
  *next = nl ? nl + 1 : end;
  return len;
}

/* A status line ("HTTP/1.1 200 OK") marks the start of a response. */
static int is_status_line(const char *line, size_t len) {
  return len >= 5 && memcmp(line, "HTTP/", 5) == 0;
}

/* Lowercased copy of [p, p+len) as a Janet string. */
static Janet lower_string(const char *p, size_t len) {
  uint8_t *buf = janet_string_begin((int32_t)len);
  for (size_t i = 0; i < len; i++)
    buf[i] = (uint8_t)(p[i] >= 'A' && p[i] <= 'Z' ? p[i] + 32 : p[i]);
  return janet_wrap_string(janet_string_end(buf));
}

/* Parse one "Name: Value" header line into t, lowercasing the name and
   trimming leading spaces from the value. Lines with no name or no colon
   (blank lines, the status line) are ignored. */
static void put_header_line(JanetTable *t, const char *line, size_t len) {
  const char *colon = memchr(line, ':', len);
  if (!colon || colon == line)
    return;
  size_t klen = (size_t)(colon - line);
  const char *vstart = colon + 1;
  size_t vlen = len - klen - 1;
  while (vlen > 0 && *vstart == ' ') {
    vstart++;
    vlen--;
  }
  janet_table_put(t, lower_string(line, klen),
                  janet_wrap_string(
                      janet_string((const uint8_t *)vstart, (int32_t)vlen)));
}

/* curl hands the header callback every hop's headers, so a followed redirect
   leaves several "HTTP/... <headers> <blank line>" blocks in the buffer.
   Resetting on each status line keeps only the final response's headers;
   duplicate names within a response keep the last value (puts overwrite). */
static Janet parse_headers(const char *raw, size_t len) {
  const char *end = raw + len;
  const char *scan = raw;
  JanetTable *t = janet_table(8);
  while (scan < end) {
    const char *next;
    size_t line_len = next_line(scan, end, &next);
    if (is_status_line(scan, line_len))
      janet_table_clear(t);
    else
      put_header_line(t, scan, line_len);
    scan = next;
  }
  return janet_wrap_struct(janet_table_to_struct(t));
}

static char *strdup_bytes(const uint8_t *bytes, int32_t len) {
  char *s = malloc((size_t)len + 1);
  if (!s)
    janet_panic("out of memory");
  memcpy(s, bytes, len);
  s[len] = '\0';
  return s;
}

/* True if the bytes contain a NUL, CR, or LF. Such bytes would either truncate
   a value handed to libcurl as a C string or smuggle extra lines into the
   request, so they are rejected wherever user input becomes a request field. */
static int has_ctl_chars(const uint8_t *bytes, int32_t len) {
  return memchr(bytes, '\0', len) || memchr(bytes, '\r', len) ||
         memchr(bytes, '\n', len);
}

/* Fetch a string argument, rejecting embedded NUL/CR/LF. A NUL would truncate
   the URL or method when handed to libcurl as a C string; CR/LF in the method
   would be written straight into the request line. */
static const char *checked_string(Janet *argv, int32_t n, const char *what) {
  JanetString s = janet_getstring(argv, n);
  int32_t len = janet_string_length(s);
  if (has_ctl_chars(s, len))
    janet_panicf("%s contains an embedded NUL, CR, or LF", what);
  return (const char *)s;
}

static ReqHandle *rh_new(const char *method, const char *url) {
  ReqHandle *rh = calloc(1, sizeof(ReqHandle));
  if (!rh)
    janet_panic("out of memory");
  rh->easy = curl_easy_init();
  if (!rh->easy) {
    free(rh);
    janet_panic("curl_easy_init failed");
  }
  rh->url = strdup(url);
  rh->method = strdup(method);
  /* Default User-Agent of "curl/<version>" derived from the linked libcurl:
     blends into the most common automated-client traffic and satisfies servers
     that reject a missing UA, without fingerprinting this library. Overridden
     by :user-agent. */
  const curl_version_info_data *ver = curl_version_info(CURLVERSION_NOW);
  char ua[64];
  snprintf(ua, sizeof(ua), "curl/%s", ver && ver->version ? ver->version : "");
  rh->user_agent = strdup(ua);
  if (!rh->url || !rh->method || !rh->user_agent) {
    rh_free(rh);
    janet_panic("out of memory");
  }
  rh->follow_redirects = 1;
  rh->max_redirects = 50;
  rh->keep_alive = 1;
  /* max_response_size stays 0 (unlimited) unless the caller sets
     :max-response-size; response headers are bounded by libcurl itself. */
  return rh;
}

/* Read a non-negative number option, returning `fallback` if it is absent. */
static double opt_nonneg(Janet opts, const char *key, double fallback) {
  Janet v = janet_get(opts, janet_ckeywordv(key));
  if (!janet_checktype(v, JANET_NUMBER))
    return fallback;
  double n = janet_unwrap_number(v);
  if (n < 0)
    janet_panicf("%s must be non-negative", key);
  return n;
}

/* Copy a string option into *dst (freeing any previous value), rejecting an
   embedded NUL/CR/LF that could truncate the value or inject a header line.
   Leaves *dst untouched if the option is absent. */
static void opt_checked_dup(Janet opts, const char *key, char **dst) {
  const uint8_t *bytes;
  int32_t len;
  Janet v = janet_get(opts, janet_ckeywordv(key));
  if (!janet_bytes_view(v, &bytes, &len))
    return;
  if (has_ctl_chars(bytes, len))
    janet_panicf("%s contains an embedded NUL, CR, or LF", key);
  free(*dst);
  *dst = strdup_bytes(bytes, len);
}

static void rh_apply_opts(ReqHandle *rh, Janet opts) {
  if (janet_checktype(opts, JANET_NIL))
    return;
  if (!janet_checktype(opts, JANET_TABLE) &&
      !janet_checktype(opts, JANET_STRUCT))
    janet_panicf("expected table or struct for options, got %t", opts);

  Janet v;
  const uint8_t *bytes;
  int32_t blen;
  const Janet *items;
  int32_t items_len;

  v = janet_get(opts, janet_ckeywordv("body"));
  if (janet_bytes_view(v, &bytes, &blen)) {
    rh->body = strdup_bytes(bytes, blen);
    rh->body_len = (size_t)blen;
  }

  v = janet_get(opts, janet_ckeywordv("follow-redirects"));
  if (!janet_checktype(v, JANET_NIL))
    rh->follow_redirects = janet_truthy(v);

  /* A negative max-redirects would tell curl to follow redirects without
     limit; opt_nonneg rejects it. */
  rh->max_redirects = (long)opt_nonneg(opts, "max-redirects", rh->max_redirects);
  rh->max_response_size =
      (size_t)opt_nonneg(opts, "max-response-size", (double)rh->max_response_size);

  /* user-agent and the basic-auth credentials all become C strings handed to
     libcurl, so each is NUL/CR/LF-checked. */
  opt_checked_dup(opts, "user-agent", &rh->user_agent);
  opt_checked_dup(opts, "username", &rh->username);
  opt_checked_dup(opts, "password", &rh->password);

  v = janet_get(opts, janet_ckeywordv("keep-alive"));
  if (!janet_checktype(v, JANET_NIL))
    rh->keep_alive = janet_truthy(v);

  v = janet_get(opts, janet_ckeywordv("headers"));
  if (janet_indexed_view(v, &items, &items_len)) {
    struct curl_slist *list = NULL;
    for (int32_t i = 0; i < items_len; i++) {
      const uint8_t *hdr;
      int32_t hdr_len;
      if (!janet_bytes_view(items[i], &hdr, &hdr_len))
        continue;
      /* Janet buffers are not NUL-terminated; copy by length so
         curl_slist_append cannot read past the bytes. Reject embedded NUL/CR/LF
         so a header value cannot be truncated or smuggle extra header lines. */
      if (has_ctl_chars(hdr, hdr_len)) {
        curl_slist_free_all(list);
        janet_panic("header contains an embedded NUL, CR, or LF");
      }
      char *h = strdup_bytes(hdr, hdr_len);
      list = curl_slist_append(list, h);
      free(h);
    }
    rh->req_headers = list;
  }
}

static void rh_configure_curl(ReqHandle *rh) {
  curl_easy_setopt(rh->easy, CURLOPT_URL, rh->url);
  /* Restrict to HTTP(S); libcurl otherwise honors file://, gopher://, etc. */
  curl_easy_setopt(rh->easy, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(rh->easy, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(rh->easy, CURLOPT_CUSTOMREQUEST, rh->method);
  curl_easy_setopt(rh->easy, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(rh->easy, CURLOPT_ERRORBUFFER, rh->error);
  curl_easy_setopt(rh->easy, CURLOPT_WRITEFUNCTION, buf_append);
  curl_easy_setopt(rh->easy, CURLOPT_WRITEDATA, &rh->body_buf);
  curl_easy_setopt(rh->easy, CURLOPT_HEADERFUNCTION, buf_append);
  curl_easy_setopt(rh->easy, CURLOPT_HEADERDATA, &rh->headers_buf);
  /* Bound the response body. buf_append enforces the cap as data streams in
     (covering chunked responses); MAXFILESIZE rejects an honest Content-Length
     up front. The header buffer is left to libcurl's own header-size limit. */
  rh->body_buf.max = rh->max_response_size;
  if (rh->max_response_size > 0)
    curl_easy_setopt(rh->easy, CURLOPT_MAXFILESIZE_LARGE,
                     (curl_off_t)rh->max_response_size);
  curl_easy_setopt(rh->easy, CURLOPT_FOLLOWLOCATION,
                   (long)rh->follow_redirects);
  curl_easy_setopt(rh->easy, CURLOPT_MAXREDIRS, rh->max_redirects);
  curl_easy_setopt(rh->easy, CURLOPT_USERAGENT, rh->user_agent);
  curl_easy_setopt(rh->easy, CURLOPT_TCP_KEEPALIVE, (long)rh->keep_alive);
  curl_easy_setopt(rh->easy, CURLOPT_PRIVATE, rh);

  if (rh->username)
    curl_easy_setopt(rh->easy, CURLOPT_USERNAME, rh->username);
  if (rh->password)
    curl_easy_setopt(rh->easy, CURLOPT_PASSWORD, rh->password);
  if (rh->req_headers)
    curl_easy_setopt(rh->easy, CURLOPT_HTTPHEADER, rh->req_headers);

  if (strcmp(rh->method, "HEAD") == 0)
    curl_easy_setopt(rh->easy, CURLOPT_NOBODY, 1L);

  if (rh->body) {
    curl_easy_setopt(rh->easy, CURLOPT_POSTFIELDS, rh->body);
    curl_easy_setopt(rh->easy, CURLOPT_POSTFIELDSIZE, (long)rh->body_len);
  }
}

static ReqHandle *req_build(const char *method, const char *url, Janet opts) {
  ReqHandle *rh = rh_new(method, url);
  rh_apply_opts(rh, opts);
  rh_configure_curl(rh);
  return rh;
}

static JANET_NO_RETURN void start_request(ReqHandle *rh) {
  pthread_once(&g_init_once, multi_init);

  rh->fiber = janet_root_fiber();
  janet_gcroot(janet_wrap_fiber(rh->fiber));
  janet_ev_inc_refcount();

  pthread_mutex_lock(&g_ms.lock);
  curl_multi_add_handle(g_ms.multi, rh->easy);
  pthread_mutex_unlock(&g_ms.lock);

  wake_curl_thread(g_ms.wakeup_pipe[1]);

  janet_await();
}

static JANET_NO_RETURN void dispatch(const char *method, int32_t argc,
                                     Janet *argv) {
  start_request(req_build(method, checked_string(argv, 0, "url"),
                          argc > 1 ? argv[1] : janet_wrap_nil()));
}

static Janet cfun_request(int32_t argc, Janet *argv) {
  janet_arity(argc, 2, 3);
  start_request(req_build(checked_string(argv, 0, "method"),
                          checked_string(argv, 1, "url"),
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
  /* curl_easy_escape treats length 0 as "call strlen", which would read past a
     non-NUL-terminated Janet buffer; an empty input encodes to an empty string. */
  if (len == 0)
    return janet_cstringv("");
  char *encoded = curl_easy_escape(NULL, (const char *)s, (int)len);
  if (!encoded)
    janet_panic("curl_easy_escape failed");
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
    if (janet_checktype(kvs[i].key, JANET_NIL))
      continue;
    JanetString ks = janet_to_string(kvs[i].key);
    JanetString vs = janet_to_string(kvs[i].value);
    char *ek =
        curl_easy_escape(NULL, (const char *)ks, janet_string_length(ks));
    char *ev =
        curl_easy_escape(NULL, (const char *)vs, janet_string_length(vs));
    if (!ek || !ev) {
      curl_free(ek);
      curl_free(ev);
      janet_panic("curl_easy_escape failed");
    }
    if (!first)
      janet_buffer_push_u8(buf, '&');
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
     "Perform an arbitrary HTTP request. method is a string (\"GET\", "
     "\"POST\", etc.).\n"
     "options is an optional table or struct:\n"
     "  :body              string or buffer - request body\n"
     "  :headers           array of \"Key: Value\" strings\n"
     "  :follow-redirects  boolean (default true)\n"
     "  :max-redirects     integer (default 50)\n"
     "  :max-response-size integer - cap on response body bytes (0 = no cap)\n"
     "  :user-agent        string (default \"curl/<version>\")\n"
     "  :keep-alive        boolean (default true)\n"
     "  :username          string - basic auth\n"
     "  :password          string - basic auth\n"
     "Returns @{:status n :body string :headers struct}."},
    {"get", cfun_get, "(http/get url &opt options)\n\nGET url."},
    {"post", cfun_post,
     "(http/post url &opt options)\n\nPOST to url. Pass :body in options."},
    {"put", cfun_put,
     "(http/put url &opt options)\n\nPUT to url. Pass :body in options."},
    {"patch", cfun_patch,
     "(http/patch url &opt options)\n\nPATCH url. Pass :body in options."},
    {"delete", cfun_delete, "(http/delete url &opt options)\n\nDELETE url."},
    {"head", cfun_head, "(http/head url &opt options)\n\nHEAD url."},
    {"options", cfun_options,
     "(http/options url &opt options)\n\nOPTIONS url."},
    {"trace", cfun_trace, "(http/trace url &opt options)\n\nTRACE url."},
    {"url-encode", cfun_url_encode,
     "(http/url-encode s)\n\nPercent-encode a string for use in a URL."},
    {"form-encode", cfun_form_encode,
     "(http/form-encode dict)\n\n"
     "Encode a table or struct as application/x-www-form-urlencoded.\n"
     "Keys and values are coerced to strings and percent-encoded."},
    {NULL, NULL, NULL}};

JANET_MODULE_ENTRY(JanetTable *env) {
  curl_global_init(CURL_GLOBAL_ALL);
  janet_cfuns(env, "http", cfuns);
}
