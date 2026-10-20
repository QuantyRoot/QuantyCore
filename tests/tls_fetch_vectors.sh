#!/bin/sh
# Checks out the vector suites the TLS tests read, at the commits pinned in
# ACVP_COMMIT and WYCHEPROOF_COMMIT, into the directory given as $1.
# ACVP is large, so only the algorithm directories in use are checked out.
set -eu

dest=$1
: "${ACVP_COMMIT:?}" "${WYCHEPROOF_COMMIT:?}"

fetch() {
    dir=$dest/$1
    git init --quiet "$dir"
    git -C "$dir" remote add origin "$2"
    if [ -n "$4" ]; then
        git -C "$dir" sparse-checkout set --no-cone $4
    fi
    git -C "$dir" fetch --quiet --depth 1 --filter=blob:none origin "$3"
    git -C "$dir" checkout --quiet FETCH_HEAD
}

fetch acvp https://github.com/usnistgov/ACVP-Server "$ACVP_COMMIT" \
    "/gen-val/json-files/SHA2-256-1.0/ /gen-val/json-files/SHA2-384-1.0/
     /gen-val/json-files/SHA2-512-1.0/ /gen-val/json-files/HMAC-SHA2-256-2.0/
     /gen-val/json-files/HMAC-SHA2-384-2.0/ /gen-val/json-files/HMAC-SHA2-512-2.0/"
fetch wycheproof https://github.com/C2SP/wycheproof "$WYCHEPROOF_COMMIT" \
    "/testvectors_v1/"
