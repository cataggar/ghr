#!/bin/sh
# ghr installer — https://github.com/cataggar/ghr
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/cataggar/ghr/main/install.sh | GHR_VERSION=v0.3.1 sh
#
# Downloads the latest ghr release into a temp dir, then uses that
# bootstrap binary to self-install via `ghr install cataggar/ghr <pubkey>`,
# which re-downloads the real artifact and verifies it with the pinned
# minisign public key. The temp dir is always removed.
#
# POSIX sh — no bash-isms. Safe to pipe from curl.

set -eu

REPO="cataggar/ghr"
MINISIGN_PUBKEY="RWSbsumpaHb+N3KCEt/EUXQ5y6Kkk8r/zCb5Z4jhEuEX8x2/U5wr5QC0"

# ---------- output helpers ----------
setup_colors() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        BOLD="$(printf '\033[1m')"
        RED="$(printf '\033[31m')"
        GREEN="$(printf '\033[32m')"
        YELLOW="$(printf '\033[33m')"
        RESET="$(printf '\033[0m')"
    else
        BOLD="" RED="" GREEN="" YELLOW="" RESET=""
    fi
}

info()  { printf '%s\n' "${GREEN}==>${RESET} $*"; }
warn()  { printf '%s\n' "${YELLOW}!${RESET} $*" >&2; }
err()   { printf '%s\n' "${RED}error:${RESET} $*" >&2; }
die()   { err "$@"; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

# ---------- http client ----------
detect_http_client() {
    if has curl; then
        HTTP_CLIENT="curl"
    elif has wget; then
        HTTP_CLIENT="wget"
    else
        die "neither 'curl' nor 'wget' found — please install one and retry"
    fi
}

# http_head_location URL — print the Location: header value (no body fetched).
http_head_location() {
    case "$HTTP_CLIENT" in
        curl) curl -sI "$1" ;;
        wget) wget -qS --spider "$1" 2>&1 ;;
    esac | awk 'tolower($1) == "location:" { sub(/\r$/, "", $2); print $2 }' | tail -n1
}

# http_get URL — fetch URL to stdout, exit non-zero on HTTP error.
http_get() {
    case "$HTTP_CLIENT" in
        curl) curl -fsSL "$1" ;;
        wget) wget -qO- "$1" ;;
    esac
}

# http_download URL DEST — download URL to DEST, exit non-zero on HTTP error.
http_download() {
    case "$HTTP_CLIENT" in
        curl) curl -fSL --progress-bar -o "$2" "$1" ;;
        wget) wget -q --show-progress -O "$2" "$1" ;;
    esac
}

# ---------- detection ----------
detect_os() {
    s="$(uname -s 2>/dev/null || echo unknown)"
    case "$s" in
        Linux)  OS="linux" ;;
        Darwin) OS="macos" ;;
        MINGW*|MSYS*|CYGWIN*)
            die "Windows is not supported by install.sh — use 'pipx install ghr-bin', 'winget install ghr', or grab the .zip from the releases page"
            ;;
        *) die "unsupported operating system: $s" ;;
    esac
}

detect_arch() {
    m="$(uname -m 2>/dev/null || echo unknown)"
    case "$m" in
        x86_64|amd64)   ARCH="x64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *) die "unsupported architecture: $m (ghr publishes x64 and arm64)" ;;
    esac
}

detect_libc() {
    # Switch the Linux OS slug to 'linux-musl' when running against musl libc.
    [ "$OS" = "linux" ] || return 0
    if has ldd && ldd --version 2>&1 | grep -qi musl; then
        OS="linux-musl"
    elif [ -f /etc/alpine-release ]; then
        OS="linux-musl"
    fi
}

# ---------- version ----------
resolve_version() {
    if [ -n "${GHR_VERSION:-}" ]; then
        TAG="$GHR_VERSION"
        info "using pinned version from \$GHR_VERSION: $TAG"
        return
    fi
    # Follow the redirect on /releases/latest — no API rate limit.
    loc="$(http_head_location "https://github.com/${REPO}/releases/latest" || true)"
    TAG="$(printf '%s\n' "$loc" | sed -nE 's|.*/tag/([^/[:space:]]+).*|\1|p' | tail -n1)"
    if [ -z "$TAG" ]; then
        warn "redirect lookup failed, falling back to GitHub API"
        TAG="$(http_get "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
            | sed -nE 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
    fi
    [ -n "$TAG" ] || die "could not resolve latest ghr version (set GHR_VERSION=vX.Y.Z to pin)"
}

# ---------- install ----------
do_install() {
    # Tag is like 'v0.3.1'; the asset filename uses the bare version.
    ver="${TAG#v}"
    asset="ghr-${ver}-${OS}-${ARCH}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${TAG}/${asset}"

    info "detected: ${OS} ${ARCH}"
    info "version:  ${TAG}"

    TMP="$(mktemp -d 2>/dev/null || mktemp -d -t ghr-install)"
    trap 'rm -rf "$TMP"' EXIT INT TERM HUP

    archive="${TMP}/ghr.tar.gz"
    info "downloading ${url}"
    if ! http_download "$url" "$archive"; then
        die "failed to download ${asset} — check that this OS/arch combination is published for ${TAG}"
    fi

    # Reject absolute paths and ".." components before extracting (CWE-22).
    if tar -tzf "$archive" | grep -qE '^/|(^|/)\.\.(/|$)'; then
        die "archive contains unsafe paths — refusing to extract"
    fi

    info "extracting"
    tar -xzf "$archive" -C "$TMP"

    # The tarball contains a top-level 'ghr' binary.
    if [ ! -x "${TMP}/ghr" ]; then
        # Some archives may nest contents; locate the binary.
        found="$(find "$TMP" -maxdepth 3 -type f -name ghr -perm -u+x 2>/dev/null | head -n1)"
        [ -n "$found" ] || die "ghr binary not found in archive"
        BOOTSTRAP="$found"
    else
        BOOTSTRAP="${TMP}/ghr"
    fi

    info "running self-install with pinned minisign pubkey"
    "$BOOTSTRAP" install "$REPO" "$MINISIGN_PUBKEY"
}

post_install_hint() {
    if ! has ghr; then
        printf '\n'
        warn "ghr is installed but not on your PATH"
        warn "run:  ~/.local/bin/ghr path ensure"
        warn "or add ~/.local/bin to PATH in your shell profile"
    fi
}

main() {
    setup_colors
    detect_http_client
    detect_os
    detect_arch
    detect_libc
    resolve_version
    do_install
    post_install_hint
    info "done — run 'ghr help' to get started"
}

main "$@"
