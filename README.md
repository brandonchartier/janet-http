# Janet HTTP

A non-blocking HTTP client for Janet, backed by libcurl. Uses libcurl's multi
interface with a private epoll loop on a single background thread — the Janet
event loop stays live regardless of how many requests are in flight, and there
is no thread-per-request overhead.

`jpm install https://github.com/brandonchartier/janet-http`

---

```janet
(import http)

(def res (http/get "https://api.example.com/data"))
(print (res :status))  # 200
(print (res :body))    # response body string

# concurrent requests — all run at the same time
(def [a b c]
  (ev/gather
    (http/get "https://api.example.com/one")
    (http/get "https://api.example.com/two")
    (http/get "https://api.example.com/three")))
```

## API

All functions return `@{:status n :body string :headers struct}`. Network errors
raise an error on the calling fiber; HTTP error codes (4xx, 5xx) are returned
normally as `:status`.

Response headers are lowercased (`"content-type"`, not `"Content-Type"`).
Duplicate header names take the last value. When a redirect is followed, the
headers are those of the final response.

### `(http/get url &opt options)`
### `(http/post url &opt options)`
### `(http/put url &opt options)`
### `(http/patch url &opt options)`
### `(http/delete url &opt options)`
### `(http/head url &opt options)`
### `(http/request method url &opt options)`

`method` is any HTTP verb string. All functions accept an optional options
table or struct:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `:body` | string or buffer | — | Request body |
| `:headers` | array of strings | — | e.g. `["Content-Type: application/json"]` |
| `:follow-redirects` | boolean | `true` | Follow 3xx redirects |
| `:max-redirects` | integer | `50` | Redirect limit |
| `:max-response-size` | integer | `0` | Cap on response body bytes (`0` = no cap) |
| `:user-agent` | string | `curl/<version>` | User-Agent header |
| `:keep-alive` | boolean | `true` | TCP keep-alive |
| `:username` | string | — | Basic auth username |
| `:password` | string | — | Basic auth password |

### `(http/url-encode s)`

Percent-encode a string for use in a URL component.

```janet
(http/url-encode "hello world")  # => "hello%20world"
(http/url-encode "café")         # => "caf%C3%A9"
```

### `(http/form-encode dict)`

Encode a table or struct as `application/x-www-form-urlencoded`. Keys and values
are coerced to strings and percent-encoded.

```janet
(http/form-encode {:q "hello world" :lang "en"})
# => "q=hello%20world&lang=en"

(http/post "https://example.com/search"
  {:body (http/form-encode {:q "janet lang"})
   :headers ["Content-Type: application/x-www-form-urlencoded"]})
```

## Requirements

- Janet 1.36+
- libcurl (`libcurl4-openssl-dev` or equivalent)

## License

GPL-3.0
