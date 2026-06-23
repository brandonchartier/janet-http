(import http)

# Integration tests against a real httpbin. Defaults to the public service;
# `make test` overrides HTTPBIN_URL to point at a local httpbin launched via
# uvx, so the suite runs hermetically without depending on the public host.
(def base-url (or (os/getenv "HTTPBIN_URL") "https://httpbin.org"))
(defn- u [path] (string base-url path))

# response shape

(let [res (http/get (u "/get"))]
  (assert (= 200 (res :status)) "GET returns 200")
  (assert (string? (res :body)) "body is a string")
  (assert (not (nil? (res :headers))) "headers are present")
  (assert (not (nil? ((res :headers) "content-type"))) "content-type header is present"))

# verbs

(let [res (http/post (u "/post") {:body "hello=world"})]
  (assert (= 200 (res :status)) "POST returns 200")
  (assert (string/find "hello" (res :body)) "POST body was sent"))

(let [res (http/put (u "/put") {:body "data"})]
  (assert (= 200 (res :status)) "PUT returns 200"))

(let [res (http/patch (u "/patch") {:body "data"})]
  (assert (= 200 (res :status)) "PATCH returns 200"))

(let [res (http/delete (u "/delete"))]
  (assert (= 200 (res :status)) "DELETE returns 200"))

(let [res (http/head (u "/get"))]
  (assert (= 200 (res :status)) "HEAD returns 200")
  (assert (= "" (res :body)) "HEAD has no body"))

(let [res (http/options (u "/get"))]
  (assert (= 200 (res :status)) "OPTIONS returns 200"))

(let [res (http/trace (u "/get"))]
  (assert (number? (res :status)) "TRACE completes and returns a status"))

(let [res (http/request "GET" (u "/get"))]
  (assert (= 200 (res :status)) "request with explicit method works"))

# options

(let [res (http/get (u "/headers")
            {:headers ["X-Test-Header: janet-http"]})]
  (assert (string/find "janet-http" (res :body)) "custom request header was sent"))

# A header given as a buffer is length-copied and delivered intact (regression
# for the original out-of-bounds read on non-NUL-terminated buffers).
(let [res (http/get (u "/headers")
            {:headers [@"X-Buf-Header: from-buffer"]})]
  (assert (string/find "from-buffer" (res :body)) "buffer header was sent"))

# Non-string/buffer header entries are skipped; valid ones still go through.
(let [res (http/get (u "/headers")
            {:headers [42 "X-Real: yes"]})]
  (assert (= 200 (res :status)) "non-string header entry does not abort the request")
  (assert (string/find "yes" (res :body)) "valid header alongside a skipped one was sent"))

(let [res (http/get (u "/user-agent")
            {:user-agent "test-agent/1.0"})]
  (assert (string/find "test-agent" (res :body)) "custom user-agent was sent"))

# The default user-agent is curl/<version>, not a static library-specific
# string that would fingerprint this client.
(let [res (http/get (u "/user-agent"))]
  (assert (string/find "curl/" (res :body)) "default user-agent is curl/<version>"))

(let [res (http/get (u "/redirect/3"))]
  (assert (= 200 (res :status)) "follows redirects by default"))

(let [res (http/get (u "/redirect/3") {:follow-redirects false})]
  (assert (= 302 (res :status)) "redirect following can be disabled"))

(let [ok (try (do (http/get (u "/redirect/5") {:max-redirects 2}) true)
              ([_] false))]
  (assert (not ok) "max-redirects raises an error when limit is exceeded"))

# A redirect to a non-http(s) scheme must be blocked (CURLOPT_REDIR_PROTOCOLS_STR),
# not just a non-http(s) scheme given as the initial URL.
(let [ok (try (do (http/get (u "/redirect-to?url=file:///etc/passwd")) true)
              ([_] false))]
  (assert (not ok) "redirect to a non-http(s) scheme is rejected"))

# curl reports every hop's headers to the callback, so a followed redirect must
# still surface the final response's headers, not the intermediate hop's. The
# 302 here carries no X-Final-Header; the destination sets it.
(let [res (http/get (u (string "/redirect-to"
                               "?url=" base-url "%2Fresponse-headers"
                               "%3FX-Final-Header%3Dyes&status_code=302")))]
  (assert (= 200 (res :status)) "redirect chain completes")
  (assert (= "yes" ((res :headers) "x-final-header"))
          "headers are the final response's, not the redirect's"))

(let [res (http/get (u "/basic-auth/user/pass")
            {:username "user" :password "pass"})]
  (assert (= 200 (res :status)) "basic auth succeeds with correct credentials"))

(let [res (http/get (u "/basic-auth/user/pass")
            {:username "user" :password "wrong"})]
  (assert (= 401 (res :status)) "basic auth fails with wrong credentials"))

# :max-response-size rejects an over-large body, whether the size is known up
# front (Content-Length) or discovered as the body streams in (chunked).
(let [ok (try (do (http/get (u "/bytes/100000")
                    {:max-response-size 1024})
                  true)
              ([_] false))]
  (assert (not ok) "response over :max-response-size (Content-Length) is rejected"))

(let [ok (try (do (http/get (u "/stream-bytes/100000")
                    {:max-response-size 1024})
                  true)
              ([_] false))]
  (assert (not ok) "response over :max-response-size (streamed) is rejected"))

(let [res (http/get (u "/bytes/512") {:max-response-size 100000})]
  (assert (= 200 (res :status)) "response within :max-response-size succeeds"))

# status codes

(let [res (http/get (u "/status/404"))]
  (assert (= 404 (res :status)) "404 is returned as status, not an error"))

(let [res (http/get (u "/status/500"))]
  (assert (= 500 (res :status)) "500 is returned as status, not an error"))

# form-encode round-trip

(let [res (http/post (u "/post")
            {:body (http/form-encode {:a "1" :b "2"})
             :headers ["Content-Type: application/x-www-form-urlencoded"]})]
  (assert (= 200 (res :status)) "POST with form-encoded body returns 200")
  (assert (string/find "\"a\": \"1\"" (res :body)) "form fields were received"))

# network errors raise on the calling fiber

(let [ok (try (do (http/get "https://does-not-exist.invalid") true)
              ([_] false))]
  (assert (not ok) "bad host raises an error"))

# concurrency — the whole point

# Five 1-second requests should complete in well under 5 seconds.
(def start (os/clock))
(def results
  (ev/gather
    (http/get (u "/delay/1"))
    (http/get (u "/delay/1"))
    (http/get (u "/delay/1"))
    (http/get (u "/delay/1"))
    (http/get (u "/delay/1"))))
(def elapsed (- (os/clock) start))

(assert (= 5 (length results)) "all concurrent requests completed")
(each res results
  (assert (= 200 (res :status)) "concurrent request returned 200"))
(assert (< elapsed 4) (string/format "5 x 1s requests ran concurrently (%.2fs)" elapsed))

(print "All integration tests passed.")
