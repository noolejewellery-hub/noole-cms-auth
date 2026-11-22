
import { OAuthClient } from './oauth';

interface Env {
  GITHUB_OAUTH_ID: string;
  GITHUB_OAUTH_SECRET: string;
  GITHUB_REPO_PRIVATE?: string;
  OAUTH_STATE_SECRET: string;
}

const CMS_ORIGIN = 'https://noole-website.pages.dev';
const STATE_COOKIE = 'noole_oauth_state';
const STATE_MAX_AGE = 600;

function randomHex(bytes: number): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return Array.from(buffer, byte =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte =>
    byte.toString(16).padStart(2, '0')
  ).join('');
}

async function signState(
  nonce: string,
  secret: string
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(nonce)
  );

  return hex(new Uint8Array(signature));
}

function getCookie(
  request: Request,
  name: string
): string | null {
  const cookies = request.headers.get('Cookie') || '';

  for (const item of cookies.split(';')) {
    const [key, ...value] = item.trim().split('=');
    if (key === name) return value.join('=');
  }

  return null;
}

function stateCookie(value: string, maxAge: number): string {
  return [
    `${STATE_COOKIE}=${value}`,
    'Path=/',
    `Max-Age=${maxAge}`,
    'HttpOnly',
    'Secure',
    'SameSite=Lax'
  ].join('; ');
}

function callbackURL(url: URL): string {
  return `${url.origin}/callback?provider=github`;
}

function oauthClient(env: Env): OAuthClient {
  return new OAuthClient({
    id: env.GITHUB_OAUTH_ID,
    secret: env.GITHUB_OAUTH_SECRET,
    target: {
      tokenHost: 'https://github.com',
      tokenPath: '/login/oauth/access_token',
      authorizePath: '/login/oauth/authorize'
    }
  });
}

async function handleAuth(
  request: Request,
  url: URL,
  env: Env
): Promise<Response> {
  if (url.searchParams.get('provider') !== 'github') {
    return new Response('Invalid provider', { status: 400 });
  }

  const nonce = randomHex(32);
  const signature = await signState(
    nonce,
    env.OAUTH_STATE_SECRET
  );

  const state = `${nonce}.${signature}`;
  const repoScope =
    env.GITHUB_REPO_PRIVATE === '1'
      ? 'repo,user'
      : 'public_repo,user';

  const authorizationURL = oauthClient(env).authorizeURL({
    redirect_uri: callbackURL(url),
    scope: repoScope,
    state
  });

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizationURL,
      'Set-Cookie': stateCookie(nonce, STATE_MAX_AGE),
      'Cache-Control': 'no-store'
    }
  });
}

function callbackPage(token: string): Response {
  const payload =
    `authorization:github:success:${JSON.stringify({ token })}`;

  const script = `
    const cmsOrigin = ${JSON.stringify(CMS_ORIGIN)};
    const result = ${JSON.stringify(payload)};

    if (!window.opener) {
      document.body.textContent =
        'Please start login from the Noolé CMS admin page.';
    } else {
      function receiveMessage(event) {
        if (
          event.origin !== cmsOrigin ||
          event.source !== window.opener
        ) return;

        window.removeEventListener(
          'message', receiveMessage
        );

        window.opener.postMessage(result, cmsOrigin);
      }

      window.addEventListener(
        'message', receiveMessage
      );

      window.opener.postMessage(
        'authorizing:github',
        cmsOrigin
      );
    }
  `;

  return new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Noolé CMS Authentication</title>
</head>
<body>
<p>Completing Noolé CMS authentication...</p>
<script>${script}</script>
</body>
</html>`,
    {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy':
          "default-src 'none'; script-src 'unsafe-inline'; " +
          "style-src 'none'; base-uri 'none'; " +
          "frame-ancestors 'none'"
      }
    }
  );
}

async function handleCallback(
  request: Request,
  url: URL,
  env: Env
): Promise<Response> {
  const clearCookie = stateCookie('', 0);

  const respond = (
    message: string,
    status: number
  ): Response => new Response(message, {
    status,
    headers: {
      'Set-Cookie': clearCookie,
      'Cache-Control': 'no-store'
    }
  });

  if (url.searchParams.get('provider') !== 'github') {
    return respond('Invalid provider', 400);
  }

  if (url.searchParams.has('error')) {
    return respond('GitHub authorization was not completed', 400);
  }

  const state = url.searchParams.get('state');
  const cookieNonce = getCookie(request, STATE_COOKIE);

  if (!state || !cookieNonce) {
    return respond('Missing or expired OAuth state', 400);
  }

  const [nonce, signature, extra] = state.split('.');

  if (
    extra !== undefined ||
    !nonce ||
    !signature ||
    !/^[0-9a-f]{64}$/.test(nonce) ||
    !/^[0-9a-f]{64}$/.test(signature) ||
    nonce !== cookieNonce
  ) {
    return respond('Invalid OAuth state', 403);
  }

  const expectedSignature = await signState(
    nonce,
    env.OAUTH_STATE_SECRET
  );

  const supplied = Uint8Array.from(
    signature.match(/.{2}/g) || [],
    value => parseInt(value, 16)
  );

  const expected = Uint8Array.from(
    expectedSignature.match(/.{2}/g) || [],
    value => parseInt(value, 16)
  );

  let difference = 0;
  for (let i = 0; i < expected.length; i++) {
    difference |= expected[i] ^ supplied[i];
  }

  if (difference !== 0) {
    return respond('Invalid OAuth signature', 403);
  }

  const code = url.searchParams.get('code');

  if (!code) {
    return respond('Missing GitHub authorization code', 400);
  }

  try {
    const token = await oauthClient(env).getToken({
      code,
      redirect_uri: callbackURL(url)
    });

    if (!token || typeof token !== 'string') {
      return respond('GitHub did not return an access token', 502);
    }

    const response = callbackPage(token);
    response.headers.set('Set-Cookie', clearCookie);
    return response;
  } catch {
    return respond('GitHub token exchange failed', 502);
  }
}

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url = new URL(request.url);

    if (request.method !== 'GET') {
      return new Response('Method not allowed', {
        status: 405
      });
    }

    if (
      !env.GITHUB_OAUTH_ID ||
      !env.GITHUB_OAUTH_SECRET ||
      !env.OAUTH_STATE_SECRET
    ) {
      return new Response('OAuth configuration missing', {
        status: 500
      });
    }

    if (url.pathname === '/auth') {
      return handleAuth(request, url, env);
    }

    if (url.pathname === '/callback') {
      return handleCallback(request, url, env);
    }

    return new Response('Noolé CMS OAuth proxy');
  }
};
