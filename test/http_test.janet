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

(let [res (http/get "https://httpbin.org/user-agent"
            {:user-agent "test-agent/1.0"})]
  (assert (string/find "test-agent" (res :body)) "custom user-agent was sent"))

(let [res (http/get "https://httpbin.org/redirect/3")]
  (assert (= 200 (res :status)) "follows redirects by default"))

(let [res (http/get "https://httpbin.org/redirect/3" {:follow-redirects false})]
  (assert (= 302 (res :status)) "redirect following can be disabled"))

(let [ok (try (do (http/get "https://httpbin.org/redirect/5" {:max-redirects 2}) true)
              ([_] false))]
  (assert (not ok) "max-redirects raises an error when limit is exceeded"))

(let [res (http/get "https://httpbin.org/basic-auth/user/pass"
            {:username "user" :password "pass"})]
  (assert (= 200 (res :status)) "basic auth succeeds with correct credentials"))

(let [res (http/get "https://httpbin.org/basic-auth/user/pass"
            {:username "user" :password "wrong"})]
  (assert (= 401 (res :status)) "basic auth fails with wrong credentials"))

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
