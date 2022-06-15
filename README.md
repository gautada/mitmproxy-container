# mitmproxy-container
https://mitmproxy.org - is a free and open source interactive HTTPS proxy.


docker build --build-arg ALPINE_VERSION=3.14.6 --build-arg MITMPROXY_VERSION=7.0.4 --file Containerfile --label revision="$(git rev-parse HEAD)" --label version="$(date +%Y.%m.%d)" --no-cache --tag mitmproxy:dev .

docker run --interactive --name mitmproxy --rm --tty mitmproxy:dev /bin/ash
