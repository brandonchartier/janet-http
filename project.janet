(declare-project
  :name "http"
  :description "Non-blocking HTTP client for Janet"
  :author "Brandon Chartier"
  :license "GPL-3.0"
  :url "https://github.com/brandonchartier/janet-http"
  :repo "git+https://github.com/brandonchartier/janet-http.git")

(declare-native
  :name "http"
  :source @["janet_http.c"]
  :cflags @["-D_GNU_SOURCE"]
  :lflags @["-lcurl"])
