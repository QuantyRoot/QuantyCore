#!/bin/sh
# Checks out upstream AppArmor at the commit pinned in APPARMOR_COMMIT
# into the directory given as $1, and generates the test profiles that
# upstream's own test target generates before it runs. With "build" as
# $2, also builds apparmor_parser there, the reference the differential
# tests compare against.
set -eu

dest=$1
: "${APPARMOR_COMMIT:?}"

git init --quiet "$dest"
git -C "$dest" remote add origin https://gitlab.com/apparmor/apparmor.git
git -C "$dest" fetch --quiet --depth 1 origin "$APPARMOR_COMMIT"
git -C "$dest" checkout --quiet FETCH_HEAD

tst=$dest/parser/tst
(
    cd "$tst"
    mkdir -p simple_tests/generated_x simple_tests/generated_perms_leading \
        simple_tests/generated_perms_safe simple_tests/generated_dbus \
        simple_tests/generated_conditional
    python3 gen-xtrans.py > /dev/null
    python3 gen-dbus.py > /dev/null
    python3 gen-conditionals.py > /dev/null
)

if [ "${2:-}" = build ]; then
    (
        cd "$dest/libraries/libapparmor"
        ./autogen.sh > /dev/null 2>&1
        ./configure --without-perl --without-python --without-ruby > /dev/null
        make -j"$(nproc)" > /dev/null
    )
    make -C "$dest/parser" -j"$(nproc)" apparmor_parser > /dev/null
fi
