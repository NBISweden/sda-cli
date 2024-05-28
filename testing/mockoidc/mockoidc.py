"""Mock OAUTH2 aiohttp.web server."""

from aiohttp import web
from authlib.jose import jwt, RSAKey
from typing import Tuple, Union
import ssl
from pathlib import Path

HTTP_PROTOCOL = "http"


def _set_ssl() -> Union[ssl.SSLContext, None]:
    global HTTP_PROTOCOL
    here = Path(__file__)
    ssl_cert = here.parent / "certs" / "mockauth.pem"
    ssl_key = here.parent / "certs" / "mockauth-key.pem"
    ssl_context: Union[ssl.SSLContext, None]
    if ssl_key.is_file() and ssl_cert.is_file():
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(str(ssl_cert), str(ssl_key))
        ssl_context.check_hostname = False
        HTTP_PROTOCOL = "https"
    else:
        ssl_context = None

    return ssl_context


def _generate_token() -> Tuple:
    """Generate RSA Key pair to be used to sign token and the JWT Token itself."""
    global HTTP_PROTOCOL

    key = RSAKey.generate_key(is_private=True)
    # we set no `exp` and other claims as they are optional in a real scenario these should be set
    # See available claims here: https://www.iana.org/assignments/jwt/jwt.xhtml
    # the important claim is the "authorities"
    header = {
        "jku": f"{HTTP_PROTOCOL}://mockauth:8000/idp/profile/oidc/keyset",
        "kid": "rsa1",
        "alg": "RS256",
        "typ": "JWT",
    }
    trusted_payload = {
        "sub": "requester@demo.org",
        "aud": ["aud2", "aud3"],
        "azp": "azp",
        "scope": "openid ga4gh_passport_v1",
        "iss": "https://demo.example",
        "exp": 9999999999,
        "iat": 1561621913,
        "jti": "6ad7aa42-3e9c-4833-bd16-765cb80c2102",
    }
    untrusted_payload = {
        "sub": "requester@demo.org",
        "aud": ["aud2", "aud3"],
        "azp": "azp",
        "scope": "openid ga4gh_passport_v1",
        "iss": "https://demo2.example",
        "exp": 9999999999,
        "iat": 1561621913,
        "jti": "6ad7aa42-3e9c-4833-bd16-765cb80c2102",
    }
    empty_payload = {
        "sub": "requester@demo.org",
        "iss": "https://demo.example",
        "exp": 99999999999,
        "iat": 1547794655,
        "jti": "6ad7aa42-3e9c-4833-bd16-765cb80c2102",
    }
    # Craft passports
    passport_terms = {
        "iss": "https://demo1.example",
        "sub": "requester@demo.org",
        "ga4gh_visa_v1": {
            "type": "AcceptedTermsAndPolicies",
            "value": "https://doi.org/10.1038/s41431-018-0219-y",
            "source": "https://ga4gh.org/duri/no_org",
            "by": "dac",
            "asserted": 1568699331,
        },
        "iat": 1571144438,
        "exp": 99999999999,
        "jti": "bed0aff9-29b1-452c-b776-a6f2200b6db1",
    }
    # passport for dataset permissions 1
    passport_dataset1 = {
        "iss": "https://demo.example",
        "sub": "requester@demo.org",
        "ga4gh_visa_v1": {
            "type": "ControlledAccessGrants",
            "value": "https://doi.example/ty009.sfrrss/600.45asasga",
            "source": "https://doi.example/no_org",
            "by": "self",
            "asserted": 1568699331,
        },
        "iat": 1571144438,
        "exp": 99999999999,
        "jti": "d1d7b521-bd6b-433d-b2d5-3d874aab9d55",
    }
    # passport for dataset permissions 1
    passport_dataset2 = {
        "iss": "https://demo2.example",
        "sub": "requester@demo.org",
        "ga4gh_visa_v1": {
            "type": "ControlledAccessGrants",
            "value": "https://doi.example/ty009.sfrrss/600.45asasga",
            "source": "https://doi.example/no_org",
            "by": "self",
            "asserted": 1568699331,
        },
        "iat": 1571144438,
        "exp": 99999999999,
        "jti": "d1d7b521-bd6b-433d-b2d5-3d874aab9d55",
    }

    public_jwk = key.as_dict(is_private=False)
    private_jwk = dict(key)

    # token that contains demo dataset and trusted visas
    trusted_token = jwt.encode(header, trusted_payload, private_jwk).decode("utf-8")

    # token that contains demo dataset and untrusted visas
    untrusted_token = jwt.encode(header, untrusted_payload, private_jwk).decode("utf-8")

    # empty token
    empty_userinfo = jwt.encode(header, empty_payload, private_jwk).decode("utf-8")

    # general terms that illustrates another visatype: AcceptedTermsAndPolicies
    visa_terms_encoded = jwt.encode(header, passport_terms, private_jwk).decode("utf-8")

    # visa that contains demo dataset
    visa_dataset1_encoded = jwt.encode(header, passport_dataset1, private_jwk).decode(
        "utf-8"
    )

    # visa that contains demo dataset but issue that is not trusted
    visa_dataset2_encoded = jwt.encode(header, passport_dataset2, private_jwk).decode(
        "utf-8"
    )
    return (
        public_jwk,
        trusted_token,
        empty_userinfo,
        untrusted_token,
        visa_terms_encoded,
        visa_dataset1_encoded,
        visa_dataset2_encoded,
    )


async def fixed_response(request: web.Request) -> web.Response:
    global HTTP_PROTOCOL
    WELL_KNOWN = {
        "issuer": f"{HTTP_PROTOCOL}://mockauth:8000",
        "authorization_endpoint": f"{HTTP_PROTOCOL}://mockauth:8000/idp/profile/oidc/authorize",
        "registration_endpoint": f"{HTTP_PROTOCOL}://mockauth:8000/idp/profile/oidc/register",
        "token_endpoint": f"{HTTP_PROTOCOL}://mockauth:8000/idp/profile/oidc/token",
        "userinfo_endpoint": f"{HTTP_PROTOCOL}://mockauth:8000/idp/profile/oidc/userinfo",
        "jwks_uri": f"{HTTP_PROTOCOL}://mockauth:8000/idp/profile/oidc/keyset",
        "response_types_supported": [
            "code",
            "id_token",
            "token id_token",
            "code id_token",
            "code token",
            "code token id_token",
        ],
        "subject_types_supported": ["public", "pairwise"],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "id_token_encryption_alg_values_supported": [
            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "A128KW",
            "A192KW",
            "A256KW",
            "A128GCMKW",
            "A192GCMKW",
            "A256GCMKW",
        ],
        "id_token_encryption_enc_values_supported": ["A128CBC-HS256"],
        "id_token_signing_alg_values_supported": [
            "RS256",
            "RS384",
            "RS512",
            "HS256",
            "HS384",
            "HS512",
            "ES256",
        ],
        "userinfo_encryption_alg_values_supported": [
            "RSA1_5",
            "RSA-OAEP",
            "RSA-OAEP-256",
            "A128KW",
            "A192KW",
            "A256KW",
            "A128GCMKW",
            "A192GCMKW",
            "A256GCMKW",
        ],
        "userinfo_encryption_enc_values_supported": ["A128CBC-HS256"],
        "userinfo_signing_alg_values_supported": [
            "RS256",
            "RS384",
            "RS512",
            "HS256",
            "HS384",
            "HS512",
            "ES256",
        ],
        "request_object_signing_alg_values_supported": [
            "none",
            "RS256",
            "RS384",
            "RS512",
            "HS256",
            "HS384",
            "HS512",
            "ES256",
            "ES384",
            "ES512",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
        ],
        "claims_parameter_supported": True,
        "request_parameter_supported": True,
        "request_uri_parameter_supported": True,
        "require_request_uri_registration": True,
        "display_values_supported": ["page"],
        "scopes_supported": ["openid"],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "claims_supported": [
            "aud",
            "iss",
            "sub",
            "iat",
            "exp",
            "acr",
            "auth_time",
            "ga4gh_passport_v1",
            "remoteUserIdentifier",
        ],
    }
    return web.json_response(WELL_KNOWN)


async def jwk_response(request: web.Request) -> web.Response:
    """Mock JSON Web Key server."""
    keys = [DATA[0]]
    keys[0]["kid"] = "rsa1"
    data = {"keys": keys}
    return web.json_response(data)


async def tokens_response(request: web.Request) -> web.Response:
    """Serve generated tokens."""
    # trusted visas, empty token, untrusted visas
    data = [DATA[1], DATA[2], DATA[3]]
    return web.json_response(data)


async def userinfo(request: web.Request) -> web.Response:
    """Mock an authentication to ELIXIR AAI for GA4GH claims."""
    _bearer = request.headers.get("Authorization").split(" ")[1]
    if _bearer == DATA[2]:
        print("empty token requested")
        data = {}
        return web.json_response(data)
    if _bearer == DATA[1]:
        print("ga4gh token requested, trusted")
        data = {"ga4gh_passport_v1": [DATA[4], DATA[5]]}
        return web.json_response(data)
    if _bearer == DATA[3]:
        print("ga4gh token requested, untrusted")
        data = {"ga4gh_passport_v1": [DATA[4], DATA[6]]}
        return web.json_response(data)


def init() -> web.Application:
    """Start server."""

    app = web.Application()
    app.router.add_get("/idp/profile/oidc/keyset", jwk_response)
    app.router.add_get("/tokens", tokens_response)
    app.router.add_get("/idp/profile/oidc/userinfo", userinfo)
    app.router.add_get("/.well-known/openid-configuration", fixed_response)
    return app


if __name__ == "__main__":
    ssl_context = _set_ssl()
    DATA = _generate_token()
    web.run_app(init(), port=8000, ssl_context=ssl_context)
