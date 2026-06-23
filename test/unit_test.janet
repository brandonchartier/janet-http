(import http)

# Offline tests: encoding helpers and request-field validation. None of these
# reach the network. The validation cases are rejected during request building,
# before any connection is attempted.

# url-encode / form-encode

(assert (= "hello%20world" (http/url-encode "hello world")) "spaces are encoded")
(assert (= "foo%2Fbar" (http/url-encode "foo/bar")) "slashes are encoded")
(assert (= "caf%C3%A9" (http/url-encode "café")) "UTF-8 is encoded")
(assert (= "" (http/url-encode "")) "empty string encodes to empty")
(assert (= "" (http/url-encode @"")) "empty buffer encodes to empty")

(let [encoded (http/form-encode {:q "hello world" :lang "en"})]
  (assert (string/find "hello%20world" encoded) "form-encode encodes spaces in values")
  (assert (string/find "=" encoded) "form-encode includes = separator")
  (assert (string/find "&" encoded) "form-encode joins pairs with &"))

# Scheme restriction (rejected by curl before any connection)

(let [ok (try (do (http/get "file:///etc/passwd") true)
              ([_] false))]
  (assert (not ok) "non-http(s) schemes are rejected"))

# CR/LF and NUL rejection on request fields

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

(print "All unit tests passed.")
