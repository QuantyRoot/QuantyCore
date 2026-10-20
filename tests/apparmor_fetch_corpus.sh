#!/bin/sh
# Builds the corpus of real profiles the AppArmor tests compile, in the
# directory given as $1. Each subdirectory holds an etc/apparmor.d tree:
#
#   ubuntu-24.04, debian-13  the apparmor and apparmor-profiles packages,
#                            from the distributions' snapshot archives,
#                            pinned by SHA-256
#   upstream                 profiles/apparmor.d of upstream AppArmor at
#                            APPARMOR_COMMIT, from the checkout in $2
#   containers               the default profiles of Docker, containerd
#                            and CRI-O, rendered from their Go templates
#                            at pinned commits with tests/apparmor_render.go,
#                            once with the host's tunables and abstractions
#                            available and once without
set -eu

dest=$1
upstream=$2
here=$(cd "$(dirname "$0")" && pwd)

deb() {
    name=$1 url=$2 sum=$3 into=$4
    curl --fail --silent --show-error --retry 3 -L -o "$dest/$name" "$url"
    echo "$sum  $dest/$name" | sha256sum -c --quiet
    mkdir -p "$into"
    dpkg-deb -x "$dest/$name" "$into"
    rm "$dest/$name"
}

ubuntu=https://snapshot.ubuntu.com/ubuntu/20261015T000000Z/pool/main/a/apparmor
deb ub1.deb "$ubuntu/apparmor_4.0.1really4.0.1-0ubuntu0.24.04.9_amd64.deb" \
    59af23f557d666039708ec176aa056d2fd85125dabd452accf6d86f5c608fb74 "$dest/ubuntu-24.04"
deb ub2.deb "$ubuntu/apparmor-profiles_4.0.1really4.0.1-0ubuntu0.24.04.9_all.deb" \
    90b02aa006eea7702cd4e851343e469e41365dda42145a3cb035de1d6c773b8c "$dest/ubuntu-24.04"

debian=https://snapshot.debian.org/archive/debian/20251001T000000Z/pool/main/a/apparmor
deb db1.deb "$debian/apparmor_4.1.0-1_amd64.deb" \
    a08bf026cde3895f76d27cb5f9ba3d31d0ecf8b5b00cab9b70edaa7473d4b0a1 "$dest/debian-13"
deb db2.deb "$debian/apparmor-profiles_4.1.0-1_all.deb" \
    86c8a5540f9b7afb9f64f20605926fc94043c12aff92ee32bd93d01c9fa71f10 "$dest/debian-13"

mkdir -p "$dest/upstream/etc"
cp -r "$upstream/profiles/apparmor.d" "$dest/upstream/etc/apparmor.d"

# The container profiles include tunables and abstractions; the Ubuntu
# tree provides them, the same files a host would have.
c=$dest/containers/etc/apparmor.d
mkdir -p "$c"
cp -r "$dest/ubuntu-24.04/etc/apparmor.d/tunables" \
    "$dest/ubuntu-24.04/etc/apparmor.d/abstractions" \
    "$dest/ubuntu-24.04/etc/apparmor.d/abi" "$c/"
tpl=$dest/templates
mkdir -p "$tpl"
gh=https://raw.githubusercontent.com
curl --fail --silent --show-error --retry 3 -o "$tpl/moby.go.txt" \
    "$gh/moby/profiles/4b8214fc4971e06172938a1f1554ccff6647ee80/apparmor/template.go"
curl --fail --silent --show-error --retry 3 -o "$tpl/containerd.go.txt" \
    "$gh/containerd/containerd/926009266892d80087b532f7f17ea14b43c4f23d/contrib/apparmor/template.go"
curl --fail --silent --show-error --retry 3 -o "$tpl/common.go.txt" \
    "$gh/containers/common/82146f3af4750038f936ec9cd804d12a837e5cde/pkg/apparmor/apparmor_linux_template.go"

# go run takes every argument ending in .go for a source file, so the
# templates are kept as .go.txt.
render() {
    go run "$here/apparmor_render.go" "$tpl/$1.go.txt" "$2" "$3" > "$c/$4"
}
with='"Imports":["#include <tunables/global>"],"InnerImports":["#include <abstractions/base>"]'
without='"Imports":["@{PROC}=/proc/"],"InnerImports":[]'
render moby baseTemplate \
    "{\"Abi\":\"abi/3.0\",\"Name\":\"docker-default\",\"PeerName\":\"docker-default\",\"DaemonProfile\":\"unconfined\",$with}" \
    docker-default
render moby baseTemplate \
    "{\"Abi\":\"\",\"Name\":\"docker-bare\",\"PeerName\":\"docker-bare\",\"DaemonProfile\":\"unconfined\",$without}" \
    docker-bare
render containerd defaultTemplate \
    "{\"Abi\":\"abi/3.0\",\"Name\":\"cri-containerd.apparmor.d\",\"DaemonProfile\":\"unconfined\",\"RootlessKit\":\"\",$with}" \
    cri-containerd.apparmor.d
render containerd defaultTemplate \
    "{\"Abi\":\"\",\"Name\":\"containerd-bare\",\"DaemonProfile\":\"unconfined\",\"RootlessKit\":\"\",$without}" \
    containerd-bare
render common defaultProfileTemplate \
    "{\"Name\":\"crio-default\",\"Version\":5000002,$with}" \
    crio-default
render common defaultProfileTemplate \
    "{\"Name\":\"crio-bare\",\"Version\":5000002,$without}" \
    crio-bare
