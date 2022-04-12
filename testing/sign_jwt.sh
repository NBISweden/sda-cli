#!/usr/bin/env bash

# Inspired by implementation by Will Haley at:
#   http://willhaley.com/blog/generate-jwt-with-bash/

set -o pipefail

# Shared content to use as template
header_template='{
    "typ": "JWT",
    "kid": "0001"
}'

build_header() {
        jq -c \
                --arg iat_str "$(date +%s)" \
                --arg alg "${1}" \
        '
        ($iat_str | tonumber) as $iat
        | .alg = $alg
        | .iat = $iat
        | .exp = ($iat + 86400)
        ' <<<"$header_template" | tr -d '\n'
}

b64enc() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }
json() { jq -c . | LC_CTYPE=C tr -d '\n'; }
rs_sign() { openssl dgst -binary -sha"${1}" -sign <(printf '%s\n' "$2"); }
es_sign() { openssl dgst -binary -sha"${1}" -sign <(printf '%s\n' "$2") | openssl asn1parse -inform DER | grep INTEGER | cut -d ':' -f 4 | xxd -p -r ; }

sign() {
        if [ -n "$2" ];then
            rsa_secret=$(<"$2")
        else
            echo "no signing key supplied"
            exit 1
        fi
        local algo payload header sig secret=$rsa_secret
        algo=${1:-RS256}; algo=${algo^^}
        header=$(build_header "$algo") || return
        payload=${3:-$test_payload}
        signed_content="$(json <<<"$header" | b64enc).$(json <<<"$payload" | b64enc)"
        case $algo in
                RS*) sig=$(printf %s "$signed_content" | rs_sign "${algo#RS}" "$secret" | b64enc) ;;
                ES*) sig=$(printf %s "$signed_content" | es_sign "${algo#ES}" "$secret" | b64enc) ;;
                *) echo "Unknown algorithm" >&2; return 1 ;;
        esac
        printf '%s.%s\n' "${signed_content}" "${sig}"
}

iat=$(date +%s)
exp=$(date --date=tomorrow +%s)

test_payload='{
  "at_hash": "J_fA458SPsXFV6lJQL1l-w",
  "aud": "XC56EL11xx",
  "email": "dummy.tester@example.org",
  "exp": '"$exp"',
  "iat": '"$iat"',
  "iss": "https://dummy.ega.nbis.se",
  "kid": "d87f2d01d1a4abb16e1eb88f6561e5067f3a6430174b8fcd0b6bf61434d6c5c8",
  "name": "Dummy Tester",
  "sid": "1ad14eb5-9b51-40c0-a52a-154a5a3792d5",
  "sub": "dummy"
}'


sign "$@"
