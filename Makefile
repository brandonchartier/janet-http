setup:
	apt-get install -y libcurl4-openssl-dev

deps:
	jpm deps

build: deps
	jpm build

test: build
	jpm test
