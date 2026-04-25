#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <janet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

/* --- Dynamic buffer --- */

typedef struct {
  char *data;
  size_t len;
} Buf;

static size_t buf_append(char *ptr, size_t size, size_t nmemb, void *ud) {
  Buf *buf = (Buf *)ud;
  size_t n = size * nmemb;
  char *tmp = realloc(buf->data, buf->len + n + 1);
  if (!tmp)
    return 0;
  buf->data = tmp;
  memcpy(buf->data + buf->len, ptr, n);
  buf->len += n;
  buf->data[buf->len] = '\0';
  return n;
}

/* --- Per-request state --- */

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
  struct curl_slist *req_headers;
  long status;
  Buf body_buf;
  Buf headers_buf;
  char error[CURL_ERROR_SIZE];
  JanetFiber *fiber;
} ReqHandle;

static void rh_free(ReqHandle *rh) {
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

/* --- Global curl_multi state --- */

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

/* --- Forward declarations --- */

static void on_complete(JanetEVGenericMessage msg);
static void *curl_thread(void *arg);
static Janet parse_headers(const char *raw, size_t len);

/* --- curl callbacks (called from within background thread, lock held) --- */

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

static int timer_cb(CURLM *multi, long timeout_ms, void *userp) {
  (void)multi;
  (void)timeout_ms;
  MultiState *ms = (MultiState *)userp;
  char byte = 0;
  /* Fire-and-forget: if the pipe is full the thread is already active. */
  write(ms->wakeup_pipe[1], &byte, 1);
  return 0;
}

/* --- Background thread --- */

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

    check_completions(ms);
    pthread_mutex_unlock(&ms->lock);
  }
  return NULL;
}

/* --- Initialization (called once via pthread_once) --- */

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

/* --- Main-thread completion callback --- */

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

/* --- Header parsing --- */

static Janet parse_headers(const char *raw, size_t len) {
  const char *p = raw;
  const char *end = raw + len;

  while (p < end && *p != '\n')
    p++;
  if (p < end)
    p++;

  int count = 0;
  const char *scan = p;
  while (scan < end) {
    const char *nl = memchr(scan, '\n', end - scan);
    if (!nl)
      break;
    size_t line_len = nl - scan;
    if (line_len > 0 && scan[line_len - 1] == '\r')
      line_len--;
    if (line_len == 0)
      break;
    if (memchr(scan, ':', line_len))
      count++;
    scan = nl + 1;
  }

  JanetKV *st = janet_struct_begin(count);
  scan = p;
  while (scan < end) {
    const char *nl = memchr(scan, '\n', end - scan);
    if (!nl)
      break;
    size_t line_len = nl - scan;
    if (line_len > 0 && scan[line_len - 1] == '\r')
      line_len--;
    if (line_len == 0) {
      scan = nl + 1;
      break;
    }

    const char *colon = memchr(scan, ':', line_len);
    if (colon) {
      size_t klen = colon - scan;
      const char *vstart = colon + 1;
      size_t vlen = line_len - klen - 1;
      while (vlen > 0 && *vstart == ' ') {
        vstart++;
        vlen--;
      }
      char *kbuf = malloc(klen);
      for (size_t i = 0; i < klen; i++)
        kbuf[i] =
            (char)(scan[i] >= 'A' && scan[i] <= 'Z' ? scan[i] + 32 : scan[i]);
      janet_struct_put(
          st,
          janet_wrap_string(janet_string((const uint8_t *)kbuf, (int32_t)klen)),
          janet_wrap_string(
              janet_string((const uint8_t *)vstart, (int32_t)vlen)));
      free(kbuf);
    }
    scan = nl + 1;
  }
  return janet_wrap_struct(janet_struct_end(st));
}

/* --- Helpers --- */

static char *strdup_bytes(const uint8_t *bytes, int32_t len) {
  char *s = malloc(len + 1);
  memcpy(s, bytes, len);
  s[len] = '\0';
  return s;
}

/* --- Request construction --- */

static ReqHandle *req_build(const char *method, const char *url, Janet opts) {
  if (!janet_checktype(opts, JANET_NIL) &&
      !janet_checktype(opts, JANET_TABLE) &&
      !janet_checktype(opts, JANET_STRUCT))
    janet_panicf("expected table or struct for options, got %t", opts);

  ReqHandle *rh = calloc(1, sizeof(ReqHandle));

  rh->easy = curl_easy_init();
  if (!rh->easy) {
    free(rh);
    janet_panic("curl_easy_init failed");
  }

  rh->url = strdup(url);
  rh->method = strdup(method);
  rh->follow_redirects = 1;
  rh->max_redirects = 50;
  rh->user_agent = strdup("janet http client");
  rh->keep_alive = 1;

  if (!janet_checktype(opts, JANET_NIL)) {
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

    v = janet_get(opts, janet_ckeywordv("max-redirects"));
    if (janet_checktype(v, JANET_NUMBER))
      rh->max_redirects = (long)janet_unwrap_number(v);

    v = janet_get(opts, janet_ckeywordv("user-agent"));
    if (janet_bytes_view(v, &bytes, &blen)) {
      free(rh->user_agent);
      rh->user_agent = strdup_bytes(bytes, blen);
    }

    v = janet_get(opts, janet_ckeywordv("keep-alive"));
    if (!janet_checktype(v, JANET_NIL))
      rh->keep_alive = janet_truthy(v);

    v = janet_get(opts, janet_ckeywordv("username"));
    if (janet_bytes_view(v, &bytes, &blen))
      rh->username = strdup_bytes(bytes, blen);

    v = janet_get(opts, janet_ckeywordv("password"));
    if (janet_bytes_view(v, &bytes, &blen))
      rh->password = strdup_bytes(bytes, blen);

    v = janet_get(opts, janet_ckeywordv("headers"));
    if (janet_indexed_view(v, &items, &items_len)) {
      struct curl_slist *list = NULL;
      for (int32_t i = 0; i < items_len; i++) {
        const uint8_t *hdr;
        int32_t hdr_len;
        if (janet_bytes_view(items[i], &hdr, &hdr_len))
          list = curl_slist_append(list, (const char *)hdr);
      }
      rh->req_headers = list;
    }
  }

  /* Configure the easy handle. */
  curl_easy_setopt(rh->easy, CURLOPT_URL, rh->url);
  curl_easy_setopt(rh->easy, CURLOPT_CUSTOMREQUEST, rh->method);
  curl_easy_setopt(rh->easy, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(rh->easy, CURLOPT_ERRORBUFFER, rh->error);
  curl_easy_setopt(rh->easy, CURLOPT_WRITEFUNCTION, buf_append);
  curl_easy_setopt(rh->easy, CURLOPT_WRITEDATA, &rh->body_buf);
  curl_easy_setopt(rh->easy, CURLOPT_HEADERFUNCTION, buf_append);
  curl_easy_setopt(rh->easy, CURLOPT_HEADERDATA, &rh->headers_buf);
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

  return rh;
}

/* --- Request dispatch --- */

static JANET_NO_RETURN void start_request(ReqHandle *rh) {
  pthread_once(&g_init_once, multi_init);

  rh->fiber = janet_root_fiber();
  janet_gcroot(janet_wrap_fiber(rh->fiber));
  janet_ev_inc_refcount();

  pthread_mutex_lock(&g_ms.lock);
  curl_multi_add_handle(g_ms.multi, rh->easy);
  pthread_mutex_unlock(&g_ms.lock);

  char byte = 0;
  write(g_ms.wakeup_pipe[1], &byte, 1);

  janet_await();
}

static JANET_NO_RETURN void dispatch(const char *method, int32_t argc,
                                     Janet *argv) {
  start_request(req_build(method, (const char *)janet_getstring(argv, 0),
                          argc > 1 ? argv[1] : janet_wrap_nil()));
}

/* --- Janet C functions --- */

static Janet cfun_request(int32_t argc, Janet *argv) {
  janet_arity(argc, 2, 3);
  start_request(req_build((const char *)janet_getstring(argv, 0),
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
     "  :body            string or buffer - request body\n"
     "  :headers         array of \"Key: Value\" strings\n"
     "  :follow-redirects  boolean (default true)\n"
     "  :max-redirects   integer (default 50)\n"
     "  :user-agent      string (default \"janet http client\")\n"
     "  :keep-alive      boolean (default true)\n"
     "  :username        string - basic auth\n"
     "  :password        string - basic auth\n"
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
