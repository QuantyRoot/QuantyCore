#!/bin/sh
# Checks out the vector suites the TLS tests read into the directory given
# as $1: ACVP, Wycheproof and x509-limbo at the commits pinned in
# ACVP_COMMIT, WYCHEPROOF_COMMIT and LIMBO_COMMIT, and the CAVP zip files, which have no version, pinned
# by their SHA-256 below. ACVP is large, so only the algorithm directories
# in use are checked out.
set -eu

dest=$1
: "${ACVP_COMMIT:?}" "${WYCHEPROOF_COMMIT:?}" "${LIMBO_COMMIT:?}"

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
fetch limbo https://github.com/C2SP/x509-limbo "$LIMBO_COMMIT" "/limbo.json"

cavp() {
    mkdir -p "$dest/cavp/$1"
    curl --fail --silent --show-error --retry 3 -o "$dest/cavp/$1.zip" \
        "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/$2"
    echo "$3  $dest/cavp/$1.zip" | sha256sum -c --quiet
    unzip -q -o "$dest/cavp/$1.zip" -d "$dest/cavp/$1"
}

cavp gcm mac/gcmtestvectors.zip \
    f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023

mkdir -p "$dest/rfc"
curl --fail --silent --show-error --retry 3 -o "$dest/rfc/rfc8448.txt" \
    https://www.rfc-editor.org/rfc/rfc8448.txt
echo "6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba  $dest/rfc/rfc8448.txt" |
    sha256sum -c --quiet

cavp ecdsa dss/186-4ecdsatestvectors.zip \
    fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752
