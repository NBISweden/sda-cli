const assert = require('assert');
const camelCase = require('camelcase');
const Provider = require('oidc-provider');

const port = process.env.PORT || 3000;
// External port can legally be an empty string
const ext_port = process.env.EXTERNAL_PORT ?? process.env.PORT;
const host = process.env.HOST || "oidc" ;

const config = ['CLIENT_ID', 'CLIENT_REDIRECT_URI'].reduce((acc, v) => {
  assert(process.env[v], `${v} config missing`);
  acc[camelCase(v)] = process.env[v];
  return acc;
}, {});

const oidcConfig = {

  features: {
    devInteractions: true,
    discovery: true,
    registration: false,
    revocation: true,
    sessionManagement: false,
    deviceFlow: true
  },
  extraParams: [
    'extra',
  ],
  tokenEndpointAuthMethods: [
    'none',
  ],
  ttl: { AccessToken: 157784630,
    AuthorizationCode: 600,
    ClientCredentials: 600,
    DeviceCode: 120,
    IdToken: 3600,
    RefreshToken: 1209600 },
  oauthNativeApps: true,
  pkce: {
    forcedForNative: true,
    supportedMethods: ['S256']
  },
  formats: {
    default: 'opaque',
    AccessToken: 'jwt',
    RefreshToken: 'jwt'
  },
  routes: {
    authorization: process.env.AUTH_ROUTE || '/auth',
    introspection: process.env.INTROSPECTION_ROUTE || '/token/introspection',
    certificates: process.env.JWKS_ROUTE || '/jwks',
    revocation: process.env.REVOCATION_ROUTE ||'/token/revocation',
    token: process.env.TOKEN_ROUTE || '/token',
    userinfo: process.env.USERINFO_ROUTE ||'/userinfo'
  },
   scopes: [
     'openid',
     'ga4gh_passport_v1',
     'profile',
     'email',
     'offline_access'
   ],
    claims: {
      acr: null,
      sid: null,
      ga4gh_passport_v1: ['ga4gh_passport_v1'],
      auth_time: null,
      ss: null,
      openid: [ 'sub' ],
      profile: ['name', 'email']
      },

  findById: async function findById(ctx, sub, token) {
    return {
      accountId: sub,
      async claims(use, scope, claims, rejected) {
        return { name: 'Dummy Tester', email:'dummy.tester@gs.uu.se', sub, ga4gh_passport_v1: ['eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwIiwibmFtZSI6InRlc3QiLCJnYTRnaF92aXNhX3YxIjp7ImFzc2VydGVkIjoxLCJieSI6InN5c3RlbSIsInNvdXJjZSI6Imh0dHA6Ly93d3cudXUuc2UvZW4vIiwidHlwZSI6IkFmZmlsaWF0aW9uQW5kUm9sZSIsInZhbHVlIjoic3RhZmZAdXUuc2UifSwiYWRtaW4iOnRydWUsImp0aSI6InRlc3QiLCJpYXQiOjE1ODQ4OTc4NDIsImV4cCI6MTU4NDkwMTQ0Mn0.RkAULuJEaExt0zVu3_uE2BSdkHLAHRD8owqhrsrTfLI'] };
      },
    };
  },

};

const oidc = new Provider(`http://${host}${ext_port ? ':' : ''}${ext_port}`, oidcConfig);

const clients= [
  {
    application_type: 'native',
    client_id: 'sda-cli',
    client_id: config.clientId,
    redirect_uris: ['http://127.0.0.1'],
    grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token', 'authorization_code'],
    token_endpoint_auth_method: 'none',
  },
];

let server;
(async () => {
await oidc.initialize({ clients });
  server = oidc.listen(port, () => {
    console.log(
      `mock-oidc-user-server listening on port ${port}, check http://${host}:${port}/.well-known/openid-configuration`
    );
  });
})().catch(err => {
  if (server && server.listening) server.close();
  console.error(err);
  process.exitCode = 1;
});
