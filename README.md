# webhook-verify

[![CI](https://github.com/MustafaKemalV/webhook-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/MustafaKemalV/webhook-verify/actions/workflows/ci.yml)

A Spring Boot starter that verifies inbound webhook signatures for multiple providers
(Stripe, GitHub, Paddle, generic HMAC) **before the request body is parsed**, using a
`@VerifiedWebhook` annotation and a raw-body-capturing servlet filter.

## Features

- One annotation, multiple providers: Stripe, GitHub, Paddle, generic HMAC (hex or base64, e.g. Shopify).
- Verifies the **raw request body** (never a re-serialized copy), the number-one webhook footgun.
- **Constant-time** signature comparison, so timing cannot leak the secret.
- Stripe and Paddle **replay protection** via a configurable timestamp tolerance.
- Pluggable provider SPI: add a provider without touching the core.
- Fails closed: a missing or invalid signature is rejected with `401` before your handler runs.

## Supported providers

| Provider | Header | Signed payload |
|----------|--------|----------------|
| `stripe` | `Stripe-Signature` | `timestamp` + `.` + raw body (with replay window) |
| `github` | `X-Hub-Signature-256` | raw body |
| `paddle` | `Paddle-Signature` | `timestamp` + `:` + raw body (with replay window) |
| `generic-hmac` | configurable | raw body (hex or base64 encoding) |

Providers that sign the raw body with an HMAC and a shared secret (for example Shopify, which uses
base64) are covered by `generic-hmac` with the right `signature-header` and `encoding`.

## Requirements

- Java 25
- Spring Boot 4.1

## Installation

Not yet published to Maven Central. Build and install it into your local Maven repository:

```bash
git clone https://github.com/MustafaKemalV/webhook-verify.git
cd webhook-verify
mvn install
```

Then add the dependency:

```xml
<dependency>
    <groupId>io.github.mustafakemalv</groupId>
    <artifactId>webhook-verify-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Quick start

### 1. Configure your providers

```yaml
webhook-verify:
  providers:
    stripe:
      type: stripe
      secret: ${STRIPE_WEBHOOK_SECRET}
    github:
      type: github
      secret: ${GITHUB_WEBHOOK_SECRET}
    paddle:
      type: paddle
      secret: ${PADDLE_WEBHOOK_SECRET}
    shopify:
      type: generic-hmac
      secret: ${SHOPIFY_CLIENT_SECRET}
      signature-header: X-Shopify-Hmac-Sha256
      encoding: base64
    my-partner:
      type: generic-hmac
      secret: ${PARTNER_SECRET}
      signature-header: X-Partner-Signature
```

The map key (`stripe`, `github`, `shopify`, `my-partner`) is the id you reference from the annotation.

### 2. Annotate your webhook handler

```java
@RestController
public class StripeWebhookController {

    @PostMapping("/webhooks/stripe")
    @VerifiedWebhook(provider = "stripe")
    public ResponseEntity<Void> handle(@RequestBody String payload) {
        // Reached only when the signature is valid.
        return ResponseEntity.ok().build();
    }
}
```

A request with a missing or invalid signature is rejected with `401` before the handler runs.

## Configuration

| Property | Description | Default |
|----------|-------------|---------|
| `webhook-verify.providers.<id>.type` | `stripe`, `github`, `paddle` or `generic-hmac` | required |
| `webhook-verify.providers.<id>.secret` | signing secret | required |
| `webhook-verify.providers.<id>.tolerance` | replay window (Stripe, Paddle) | `5m` |
| `webhook-verify.providers.<id>.signature-header` | signature header (generic-hmac only) | required for generic |
| `webhook-verify.providers.<id>.encoding` | `hex` or `base64` (generic-hmac only) | `hex` |

## How it works

1. A servlet filter captures the raw body once and makes the request re-readable.
2. An interceptor reads `@VerifiedWebhook`, selects that provider's verifier and secret, and
   verifies the raw body against the signature header.
3. Valid: the controller runs. Invalid: `401`, and the controller never runs.

For the full design, threat model and algorithm details, see
[docs/how-it-works.md](docs/how-it-works.md).

## Security notes

- Signatures are computed over the raw bytes, never re-serialized JSON.
- Comparison is constant-time (`MessageDigest.isEqual`).
- Timestamped schemes (Stripe, Paddle) are checked against a tolerance to reject replays; for
  Stripe only the `v1` scheme is trusted and the fake `v0` test scheme is ignored.

## License

[MIT](LICENSE)
