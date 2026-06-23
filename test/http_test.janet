(import http)

# ---------------------------------------------------------------------------
# response shape
# ---------------------------------------------------------------------------

(let [res (http/get "https://httpbin.org/get")]
  (assert (= 200 (res :status)) "GET returns 200")
  (assert (string? (res :body)) "body is a string")
  (assert (not (nil? (res :headers))) "headers are present")
  (assert (not (nil? ((res :headers) "content-type"))) "content-type header is present"))

# ---------------------------------------------------------------------------
# verbs
# ---------------------------------------------------------------------------

(let [res (http/post "https://httpbin.org/post" {:body "hello=world"})]
  (assert (= 200 (res :status)) "POST returns 200")
  (assert (string/find "hello" (res :body)) "POST body was sent"))

(let [res (http/put "https://httpbin.org/put" {:body "data"})]
  (assert (= 200 (res :status)) "PUT returns 200"))

(let [res (http/patch "https://httpbin.org/patch" {:body "data"})]
  (assert (= 200 (res :status)) "PATCH returns 200"))

(let [res (http/delete "https://httpbin.org/delete")]
  (assert (= 200 (res :status)) "DELETE returns 200"))

(let [res (http/head "https://httpbin.org/get")]
  (assert (= 200 (res :status)) "HEAD returns 200")
  (assert (= "" (res :body)) "HEAD has no body"))

(let [res (http/options "https://httpbin.org/get")]
  (assert (= 200 (res :status)) "OPTIONS returns 200"))

(let [res (http/trace "https://httpbin.org/get")]
  (assert (number? (res :status)) "TRACE completes and returns a status"))

(let [res (http/request "GET" "https://httpbin.org/get")]
  (assert (= 200 (res :status)) "request with explicit method works"))

# ---------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------

(let [res (http/get "https://httpbin.org/headers"
            {:headers ["X-Test-Header: janet-http"]})]
  (assert (string/find "janet-http" (res :body)) "custom request header was sent"))

# A header given as a buffer is length-copied and delivered intact (regression
# for the original out-of-bounds read on non-NUL-terminated buffers).
(let [res (http/get "https://httpbin.org/headers"
            {:headers [@"X-Buf-Header: from-buffer"]})]
  (assert (string/find "from-buffer" (res :body)) "buffer header was sent"))

# Non-string/buffer header entries are skipped; valid ones still go through.
(let [res (http/get "https://httpbin.org/headers"
            {:headers [42 "X-Real: yes"]})]
  (assert (= 200 (res :status)) "non-string header entry does not abort the request")
  (assert (string/find "yes" (res :body)) "valid header alongside a skipped one was sent"))

(let [res (http/get "https://httpbin.org/user-agent"
            {:user-agent "test-agent/1.0"})]
  (assert (string/find "test-agent" (res :body)) "custom user-agent was sent"))

# The default user-agent is curl/<version>, not a static library-specific
# string that would fingerprint this client.
(let [res (http/get "https://httpbin.org/user-agent")]
  (assert (string/find "curl/" (res :body)) "default user-agent is curl/<version>"))

(let [res (http/get "https://httpbin.org/redirect/3")]
  (assert (= 200 (res :status)) "follows redirects by default"))

(let [res (http/get "https://httpbin.org/redirect/3" {:follow-redirects false})]
  (assert (= 302 (res :status)) "redirect following can be disabled"))

(let [ok (try (do (http/get "https://httpbin.org/redirect/5" {:max-redirects 2}) true)
              ([_] false))]
  (assert (not ok) "max-redirects raises an error when limit is exceeded"))

# A redirect to a non-http(s) scheme must be blocked (CURLOPT_REDIR_PROTOCOLS_STR),
# not just a non-http(s) scheme given as the initial URL.
(let [ok (try (do (http/get "https://httpbin.org/redirect-to?url=file:///etc/passwd")
                  true)
              ([_] false))]
  (assert (not ok) "redirect to a non-http(s) scheme is rejected"))

# curl reports every hop's headers to the callback, so a followed redirect must
# still surface the final response's headers, not the intermediate hop's. The
# 302 here carries no X-Final-Header; the destination sets it.
(let [res (http/get (string "https://httpbin.org/redirect-to"
                            "?url=https%3A%2F%2Fhttpbin.org%2Fresponse-headers"
                            "%3FX-Final-Header%3Dyes&status_code=302"))]
  (assert (= 200 (res :status)) "redirect chain completes")
  (assert (= "yes" ((res :headers) "x-final-header"))
          "headers are the final response's, not the redirect's"))

(let [res (http/get "https://httpbin.org/basic-auth/user/pass"
            {:username "user" :password "pass"})]
  (assert (= 200 (res :status)) "basic auth succeeds with correct credentials"))

(let [res (http/get "https://httpbin.org/basic-auth/user/pass"
            {:username "user" :password "wrong"})]
  (assert (= 401 (res :status)) "basic auth fails with wrong credentials"))

# :max-response-size rejects an over-large body, whether the size is known up
# front (Content-Length) or discovered as the body streams in (chunked).
(let [ok (try (do (http/get "https://httpbin.org/bytes/100000"
                    {:max-response-size 1024})
                  true)
              ([_] false))]
  (assert (not ok) "response over :max-response-size (Content-Length) is rejected"))

(let [ok (try (do (http/get "https://httpbin.org/stream-bytes/100000"
                    {:max-response-size 1024})
                  true)
              ([_] false))]
  (assert (not ok) "response over :max-response-size (streamed) is rejected"))

(let [res (http/get "https://httpbin.org/bytes/512" {:max-response-size 100000})]
  (assert (= 200 (res :status)) "response within :max-response-size succeeds"))

# ---------------------------------------------------------------------------
# status codes
# ---------------------------------------------------------------------------

(let [res (http/get "https://httpbin.org/status/404")]
  (assert (= 404 (res :status)) "404 is returned as status, not an error"))

(let [res (http/get "https://httpbin.org/status/500")]
  (assert (= 500 (res :status)) "500 is returned as status, not an error"))

# ---------------------------------------------------------------------------
# url-encode / form-encode
# ---------------------------------------------------------------------------

(assert (= "hello%20world" (http/url-encode "hello world")) "spaces are encoded")
(assert (= "foo%2Fbar" (http/url-encode "foo/bar")) "slashes are encoded")
(assert (= "caf%C3%A9" (http/url-encode "café")) "UTF-8 is encoded")
(assert (= "" (http/url-encode "")) "empty string encodes to empty")

(let [encoded (http/form-encode {:q "hello world" :lang "en"})]
  (assert (string/find "hello%20world" encoded) "form-encode encodes spaces in values")
  (assert (string/find "=" encoded) "form-encode includes = separator")
  (assert (string/find "&" encoded) "form-encode joins pairs with &"))

(let [res (http/post "https://httpbin.org/post"
            {:body (http/form-encode {:a "1" :b "2"})
             :headers ["Content-Type: application/x-www-form-urlencoded"]})]
  (assert (= 200 (res :status)) "POST with form-encoded body returns 200")
  (assert (string/find "\"a\": \"1\"" (res :body)) "form fields were received"))

# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------

(let [ok (try (do (http/get "https://does-not-exist.invalid") true)
              ([_] false))]
  (assert (not ok) "bad host raises an error"))

# ---------------------------------------------------------------------------
# input validation
# ---------------------------------------------------------------------------

(let [ok (try (do (http/get "file:///etc/passwd") true)
              ([_] false))]
  (assert (not ok) "non-http(s) schemes are rejected"))

(let [ok (try (do (http/get "https://example.com/\r\nHost: evil") true)
              ([_] false))]
  (assert (not ok) "url with embedded CR/LF is rejected"))

(let [ok (try (do (http/get "https://exa\x00mple.com/") true)
              ([_] false))]
  (assert (not ok) "url with embedded NUL is rejected"))

(let [ok (try (do (http/request "GET\r\nEvil: 1" "https://example.com/") true)
              ([_] false))]
  (assert (not ok) "method with embedded CR/LF is rejected"))

(let [ok (try (do (http/get "https://example.com"
                    {:headers ["X-Evil: a\r\nX-Injected: yes"]})
                  true)
              ([_] false))]
  (assert (not ok) "header with embedded CR/LF is rejected"))

(let [ok (try (do (http/get "https://example.com"
                    {:user-agent "Eve\r\nX-Injected: yes"})
                  true)
              ([_] false))]
  (assert (not ok) "user-agent with embedded CR/LF is rejected"))

# Buffers are mutable and not NUL-terminated — the input class behind the
# original out-of-bounds read. The same validation must apply to them.
(let [ok (try (do (http/get "https://example.com"
                    {:headers [@"X-Evil: a\r\nX-Injected: yes"]})
                  true)
              ([_] false))]
  (assert (not ok) "header given as a buffer with CR/LF is rejected"))

(let [ok (try (do (http/get "https://example.com"
                    {:user-agent @"Eve\r\nX-Injected: yes"})
                  true)
              ([_] false))]
  (assert (not ok) "user-agent given as a buffer with CR/LF is rejected"))

# NUL is the truncation vector specifically, distinct from CR/LF.
(let [ok (try (do (http/get "https://example.com"
                    {:headers ["X-Evil: a\x00b"]})
                  true)
              ([_] false))]
  (assert (not ok) "header with embedded NUL is rejected"))

(let [ok (try (do (http/get "https://example.com"
                    {:user-agent "Eve\x00B"})
                  true)
              ([_] false))]
  (assert (not ok) "user-agent with embedded NUL is rejected"))

# Basic-auth credentials reach libcurl as C strings, so a NUL would silently
# truncate them.
(let [ok (try (do (http/get "https://example.com" {:username "us\x00er"}) true)
              ([_] false))]
  (assert (not ok) "username with embedded NUL is rejected"))

(let [ok (try (do (http/get "https://example.com" {:password "pa\x00ss"}) true)
              ([_] false))]
  (assert (not ok) "password with embedded NUL is rejected"))

# A negative max-redirects would otherwise tell curl to follow without limit.
(let [ok (try (do (http/get "https://example.com" {:max-redirects -1}) true)
              ([_] false))]
  (assert (not ok) "negative max-redirects is rejected"))

(assert (= "" (http/url-encode @""))
        "url-encode of an empty buffer is an empty string")

# ---------------------------------------------------------------------------
# concurrency — the whole point
# ---------------------------------------------------------------------------

# Five 1-second requests should complete in well under 5 seconds.
(def start (os/clock))
(def results
  (ev/gather
    (http/get "https://httpbin.org/delay/1")
    (http/get "https://httpbin.org/delay/1")
    (http/get "https://httpbin.org/delay/1")
    (http/get "https://httpbin.org/delay/1")
    (http/get "https://httpbin.org/delay/1")))
(def elapsed (- (os/clock) start))

(assert (= 5 (length results)) "all concurrent requests completed")
(each res results
  (assert (= 200 (res :status)) "concurrent request returned 200"))
(assert (< elapsed 4) (string/format "5 x 1s requests ran concurrently (%.2fs)" elapsed))

(print "All tests passed.")
