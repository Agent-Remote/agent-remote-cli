#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?target is required}"
DEST="${2:?destination is required}"
SOURCE_DEST="${3:?source destination is required}"
LICENSE_DEST="${4:?license destination is required}"

TMUX_VERSION="${TMUX_VERSION:-3.5a}"
LIBEVENT_VERSION="${LIBEVENT_VERSION:-2.1.12-stable}"
NCURSES_VERSION="${NCURSES_VERSION:-6.5}"
LIBMNL_VERSION="${LIBMNL_VERSION:-1.0.5}"
WIREGUARD_TOOLS_VERSION="${WIREGUARD_TOOLS_VERSION:-1.0.20210914}"
WIREGUARD_GO_VERSION="${WIREGUARD_GO_VERSION:-0.0.20250522}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$DEST" "$SOURCE_DEST" "$LICENSE_DEST" "$WORK/prefix"
DEST="$(cd "$DEST" && pwd)"
SOURCE_DEST="$(cd "$SOURCE_DEST" && pwd)"
LICENSE_DEST="$(cd "$LICENSE_DEST" && pwd)"

download_source() {
  local name="$1" url="$2" archive
  archive="$WORK/$name"
  curl --fail --show-error --location --retry 5 --retry-all-errors --retry-delay 5 "$url" -o "$archive"
  cp "$archive" "$SOURCE_DEST/$name"
  mkdir -p "$WORK/src/$name"
  tar -xf "$archive" -C "$WORK/src/$name" --strip-components=1
}

download_source "tmux-${TMUX_VERSION}.tar.gz" \
  "https://github.com/tmux/tmux/releases/download/${TMUX_VERSION}/tmux-${TMUX_VERSION}.tar.gz"
download_source "libevent-${LIBEVENT_VERSION}.tar.gz" \
  "https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}/libevent-${LIBEVENT_VERSION}.tar.gz"
download_source "ncurses-${NCURSES_VERSION}.tar.gz" \
  "https://ftp.gnu.org/gnu/ncurses/ncurses-${NCURSES_VERSION}.tar.gz"
download_source "wireguard-tools-${WIREGUARD_TOOLS_VERSION}.tar.xz" \
  "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-v${WIREGUARD_TOOLS_VERSION}.tar.xz"

case "$TARGET" in
  x86_64-unknown-linux-gnu)
    HOST=x86_64-linux-gnu
    CC_BIN=gcc
    TARGET_OS=linux
    ;;
  aarch64-unknown-linux-gnu)
    HOST=aarch64-linux-gnu
    CC_BIN=aarch64-linux-gnu-gcc
    TARGET_OS=linux
    ;;
  x86_64-apple-darwin|aarch64-apple-darwin)
    HOST=""
    CC_BIN=cc
    TARGET_OS=darwin
    ;;
  *)
    echo "unsupported managed-tools target: $TARGET" >&2
    exit 1
    ;;
esac

HOST_ARG="$HOST"
NCURSES_BUILD_CC=""
if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then
  NCURSES_BUILD_CC=gcc
fi

(
  cd "$WORK/src/libevent-${LIBEVENT_VERSION}.tar.gz"
  ./configure ${HOST_ARG:+--host="$HOST_ARG"} --prefix="$WORK/prefix" --disable-shared --enable-static \
    --disable-openssl --disable-samples --disable-libevent-regress
  make -j2
  make install
)
tmux_cppflags="-I$WORK/prefix/include"
tmux_libs="-levent -lncurses"
if [ "$TARGET_OS" = linux ]; then
  (
    cd "$WORK/src/ncurses-${NCURSES_VERSION}.tar.gz"
    ./configure ${HOST_ARG:+--host="$HOST_ARG"} ${NCURSES_BUILD_CC:+--with-build-cc="$NCURSES_BUILD_CC"} \
      --prefix="$WORK/prefix" --without-shared --with-normal \
      --without-debug --without-ada --without-cxx --without-cxx-binding --without-progs --without-manpages \
      --without-tests --without-tack --enable-widec
    make -j2
    make install
  )
  tmux_cppflags="$tmux_cppflags -I$WORK/prefix/include/ncursesw"
  tmux_libs="-levent -lncursesw"
fi
(
  cd "$WORK/src/tmux-${TMUX_VERSION}.tar.gz"
  if [ "$TARGET" = "aarch64-unknown-linux-gnu" ]; then
    PKG_CONFIG_PATH="$WORK/prefix/lib/pkgconfig" CPPFLAGS="$tmux_cppflags" \
      LDFLAGS="-L$WORK/prefix/lib" LIBS="$tmux_libs" \
      ac_cv_search_forkpty=-lutil CC="$CC_BIN" \
      ./configure --host="$HOST_ARG" --disable-utf8proc
  else
    PKG_CONFIG_PATH="$WORK/prefix/lib/pkgconfig" CPPFLAGS="$tmux_cppflags" \
      LDFLAGS="-L$WORK/prefix/lib" LIBS="$tmux_libs" CC="$CC_BIN" \
      ./configure ${HOST_ARG:+--host="$HOST_ARG"} --disable-utf8proc
  fi
  make -j2
  install -m 0755 tmux "$DEST/tmux"
)

if [ "$TARGET_OS" = linux ]; then
  download_source "libmnl-${LIBMNL_VERSION}.tar.bz2" \
    "https://netfilter.org/projects/libmnl/files/libmnl-${LIBMNL_VERSION}.tar.bz2"
  (
    cd "$WORK/src/libmnl-${LIBMNL_VERSION}.tar.bz2"
    CC="$CC_BIN" ./configure ${HOST_ARG:+--host="$HOST_ARG"} --prefix="$WORK/prefix" --disable-shared --enable-static
    make -j2
    make install
  )
fi

(
  cd "$WORK/src/wireguard-tools-${WIREGUARD_TOOLS_VERSION}.tar.xz/src"
  make -j2 CC="$CC_BIN" PKG_CONFIG_PATH="$WORK/prefix/lib/pkgconfig" \
    CFLAGS="-O2 -I$WORK/prefix/include -DRUNSTATEDIR=\\\"/var/run\\\"" \
    LDFLAGS="-L$WORK/prefix/lib" wg
  install -m 0755 wg "$DEST/wg"
  install -m 0755 "wg-quick/${TARGET_OS}.bash" "$DEST/wg-quick"
)

if [ "$TARGET_OS" = darwin ]; then
  download_source "wireguard-go-${WIREGUARD_GO_VERSION}.tar.gz" \
    "https://github.com/WireGuard/wireguard-go/archive/refs/tags/${WIREGUARD_GO_VERSION}.tar.gz"
  (
    cd "$WORK/src/wireguard-go-${WIREGUARD_GO_VERSION}.tar.gz"
    go build -trimpath -ldflags='-s -w' -o "$DEST/wireguard-go" .
  )
  cp "$WORK/src/wireguard-go-${WIREGUARD_GO_VERSION}.tar.gz/LICENSE" "$LICENSE_DEST/wireguard-go-LICENSE"
fi

cp "$WORK/src/tmux-${TMUX_VERSION}.tar.gz/COPYING" "$LICENSE_DEST/tmux-COPYING"
cp "$WORK/src/libevent-${LIBEVENT_VERSION}.tar.gz/LICENSE" "$LICENSE_DEST/libevent-LICENSE"
cp "$WORK/src/ncurses-${NCURSES_VERSION}.tar.gz/COPYING" "$LICENSE_DEST/ncurses-COPYING"
cp "$WORK/src/wireguard-tools-${WIREGUARD_TOOLS_VERSION}.tar.xz/COPYING" "$LICENSE_DEST/wireguard-tools-COPYING"
if [ "$TARGET_OS" = linux ]; then
  cp "$WORK/src/libmnl-${LIBMNL_VERSION}.tar.bz2/COPYING" "$LICENSE_DEST/libmnl-COPYING"
fi
