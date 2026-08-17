# webhook-verify

A Spring Boot starter that verifies inbound webhook signatures for multiple providers
(Stripe, GitHub, generic HMAC) before the request body is parsed, using a
`@VerifiedWebhook` annotation and a raw-body-capturing servlet filter.

> Status: early development. Not yet published.

## License

MIT
