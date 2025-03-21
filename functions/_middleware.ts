/**
 * Shows how to restrict access using the HTTP Basic schema.
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
 * @see https://tools.ietf.org/html/rfc7617
 *
 */

import { Buffer } from "node:buffer";

const encoder = new TextEncoder();

/**
 * Protect against timing attacks by safely comparing values using `timingSafeEqual`.
 * Refer to https://developers.cloudflare.com/workers/runtime-apis/web-crypto/#timingsafeequal for more details
 */
function timingSafeEqual(a: string, b: string) {
    const aBytes = encoder.encode(a);
    const bBytes = encoder.encode(b);

    if (aBytes.byteLength !== bBytes.byteLength) {
        // Strings must be the same length in order to compare
        // with crypto.subtle.timingSafeEqual
        return false;
    }

    return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

export async function onRequest(context: any) {
    const { request, env } = context;

    // You will need an admin password. This should be
    // attached to your Worker as an encrypted secret.
    // Refer to https://developers.cloudflare.com/workers/configuration/secrets/
    const BASIC_PASS = env.CFP_PASSWORD ?? "password";

    const url = new URL(request.url);

    if (url.pathname === "/logout") {
        // Invalidate the "Authorization" header by returning a HTTP 401.
        // We do not send a "WWW-Authenticate" header, as this would trigger
        // a popup in the browser, immediately asking for credentials again.
        return new Response("Logged out.", { status: 401 });
    }

    // The "Authorization" header is sent when authenticated.
    const authorization = request.headers.get("Authorization");
    if (!authorization) {
        return new Response("You need to login.", {
            status: 401,
            headers: {
                // Prompts the user for credentials.
                "WWW-Authenticate": 'Basic realm="my scope", charset="UTF-8"',
            },
        });
    }
    const [scheme, encoded] = authorization.split(" ");

    // The Authorization header must start with Basic, followed by a space.
    if (!encoded || scheme !== "Basic") {
        return new Response("Malformed authorization header.", {
            status: 400,
        });
    }

    const credentials = Buffer.from(encoded, "base64").toString();

    // The username and password are split by the first colon.
    //=> example: "username:password"
    const index = credentials.indexOf(":");
    // User not used for authentication!
    // const user = credentials.substring(0, index);
    const pass = credentials.substring(index + 1);

    if (
        !timingSafeEqual(BASIC_PASS, pass)
    ) {
        return new Response("You need to login.", {
            status: 401,
            headers: {
                // Prompts the user for credentials.
                "WWW-Authenticate": 'Basic realm="my scope", charset="UTF-8"',
            },
        });
    }

    // User is authenticated, allow the request to continue
    return context.next();
}