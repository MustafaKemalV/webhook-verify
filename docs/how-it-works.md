# How webhook-verify works

This document explains the design behind the library: the threat it defends against, the signing
algorithm at its core, how each provider differs, and why the request flow is built the way it is.
For usage, see the [README](../README.md).

## The problem and threat model

A webhook endpoint is a public URL that a provider (Stripe, GitHub, ...) calls with a `POST` when
something happens. Because the URL is public, anyone can call it. Without verification an attacker
could:

- **Forge** an event ("payment succeeded") your server has no way to tell from a real one.
- **Tamper** with a real event's body in transit (change an amount).
- **Replay** a captured valid request over and over.
- **Extract the secret** through a timing side channel in a naive signature comparison.

The library defends against all four. It assumes the attacker can send arbitrary requests and can
observe response timing, but does not know the shared signing secret.

## The algorithm core: HMAC-SHA256

Each provider shares a secret with you. It signs every request with that secret using HMAC-SHA256
and sends the signature in a header. You recompute the signature with the same secret and compare.

- **SHA-256** turns any input into a fixed 256-bit (64 hex chars) fingerprint. It is one-way and
  collision resistant: change one byte of input and the output changes completely.
- **HMAC** binds that hash to a secret key, `HMAC(secret, message)`, so only a holder of the secret
  can produce a valid value. Formally:

  ```
  HMAC(K, m) = SHA256( (K XOR opad) || SHA256( (K XOR ipad) || m ) )
  ```

  The two-pass, padded construction is what makes HMAC safe against length-extension attacks that
  a naive `SHA256(secret || message)` would be vulnerable to. We rely on the JDK's `Mac`
  implementation rather than hand-rolling this.

HMAC is **deterministic** (same secret and message always yield the same output), which is exactly
what makes verification possible, and **unforgeable** without the secret.

## What gets signed (signing base)

The single most error-prone detail: the signature is computed over an exact byte sequence. If even
one byte differs, verification fails. The byte sequence differs per provider:

| Provider | Signing base |
|----------|--------------|
| GitHub | the raw request body |
| Stripe | `timestamp` + `.` + the raw request body |
| generic-hmac | the raw request body |

The library always signs the **raw request bytes** and never a re-serialized copy of the JSON.

## Constant-time comparison

Comparing signatures with a normal equality check returns as soon as two bytes differ. An attacker
who can measure response time can recover the correct signature one byte at a time. The library
compares with `MessageDigest.isEqual`, which does not short-circuit and does not leak how many
leading bytes matched.

## Replay protection (Stripe)

Because Stripe's signing base includes the timestamp, an attacker cannot alter the timestamp without
invalidating the signature. So we trust the timestamp and reject deliveries whose timestamp is older
than a configurable tolerance (default 5 minutes). A captured-but-old valid request therefore fails.
Only the `v1` scheme is trusted; Stripe's fake `v0` test scheme is ignored to prevent downgrade
attacks, and multiple `v1` signatures (secret rotation) are all tried.

## Request flow

```
POST /webhooks/stripe  (raw body + signature header)
        │
        ▼
[1] CachedBodyFilter        reads the body once into a byte[] and wraps the request so it is
        │                   re-readable (a servlet stream can only be read once)
        ▼
[2] WebhookVerificationInterceptor
        │   reads @VerifiedWebhook(provider), looks up the verifier + secret for that provider
        ▼
[3] WebhookVerifier         recomputes the signature over the raw bytes and compares (constant-time),
        │                   plus the timestamp check for Stripe
        ├─ valid  ──▶ [4] controller runs; it can still read the (cached) body
        └─ invalid ─▶ 401 Unauthorized; the controller never runs
```

Two design points make this work:

- **Only a filter can make the body re-readable** for the downstream controller, so raw-body
  capture lives in `CachedBodyFilter`, registered at highest precedence.
- **Only an interceptor sees the matched handler**, so annotation reading and verification live in
  `WebhookVerificationInterceptor`.

## Fail-closed behavior

If a provider is annotated but has no configured secret, the library throws at startup rather than
silently letting requests through. A missing or invalid signature is rejected with `401` before the
controller runs. The safe default everywhere is to reject.

## Extending: the provider SPI

All providers implement one interface:

```java
public interface WebhookVerifier {
    String provider();
    VerificationResult verify(VerificationContext context);
}
```

`VerificationContext` is deliberately decoupled from the servlet API (it carries the raw bytes, a
header lookup, the secret, the tolerance and the current instant), which keeps verifiers unit
testable and lets the timestamp be injected for deterministic replay tests. Adding a provider means
writing one strategy class; the core, filter and interceptor stay untouched.
