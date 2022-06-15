ARG ALPINE_VERSION=3.15.4

# ╭――――――――――――――――-------------------------------------------------------――╮
# │                                                                         │
# │ STAGE 1: mitmproxy-container                                            │
# │                                                                         │
# ╰―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――╯
FROM alpine:$ALPINE_VERSION

# ╭――――――――――――――――――――╮
# │ METADATA           │
# ╰――――――――――――――――――――╯
LABEL source="https://github.com/gautada/mitmproxy-container.git"
LABEL maintainer="Adam Gautier <adam@gautier.org>"
LABEL description="A mitmproxy container"

# ╭――――――――――――――――――――╮
# │ VERSION            │
# ╰――――――――――――――――――――╯
ARG MITMPROXY_VERSION=7.0.4
ARG MITMPROXY_PACKAGE="$MITMPROXY_VERSION"-r2

# ╭――――――――――――――――――――╮
# │ PACKAGES           │
# ╰――――――――――――――――――――╯

# ╭――――――――――――――――――――╮
# │ PORTS              │
# ╰――――――――――――――――――――╯
EXPOSE 8000/tcp

# ╭――――――――――――――――――――╮
# │ APPLICATION        │
# ╰――――――――――――――――――――╯
# https://wiki.alpinelinux.org/wiki/Enable_Community_Repository
# RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/community/" >> /etc/apk/repositories
# RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories
# RUN apk add --no-cache mitmproxy=$MITMPROXY_PACKAGE py3-setuptools
RUN apk add --no-cache py3-pip py3-wheel python3-dev build-base shadow
RUN /usr/bin/pip install --upgrade pip && /usr/bin/pip install pycrypto
 
# ╭――――――――――――――――――――╮
# │ USER               │
# ╰――――――――――――――――――――╯
ARG USER=mitmproxy
VOLUME /opt/$USER

RUN /bin/mkdir -p /opt/$USER \
 && /usr/sbin/addgroup $USER \
 && /usr/sbin/adduser -D -s /bin/ash -G $USER $USER \
 && /usr/sbin/usermod -aG wheel $USER \
 && /bin/echo "$USER:$USER" | chpasswd \
 && /bin/chown $USER:$USER -R /opt/$USER

USER $USER
WORKDIR /home/$USER

