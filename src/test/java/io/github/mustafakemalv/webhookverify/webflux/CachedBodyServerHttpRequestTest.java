package io.github.mustafakemalv.webhookverify.webflux;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

class CachedBodyServerHttpRequestTest {

    @Test
    void captures_and_replays_the_body_more_than_once() {
        byte[] body = "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8);
        MockServerHttpRequest request = MockServerHttpRequest.post("/webhooks/x")
                .body(new String(body, StandardCharsets.UTF_8));
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        CachedBodyServerHttpRequest cached = CachedBodyServerHttpRequest.capture(exchange).block();

        assertThat(cached).isNotNull();
        assertThat(cached.getCachedBody()).isEqualTo(body);
        assertThat(readBody(cached)).isEqualTo(body);
        assertThat(readBody(cached)).isEqualTo(body); // replay: ikinci okuma da aynı
    }

    private static byte[] readBody(ServerHttpRequest request) {
        DataBuffer joined = DataBufferUtils.join(request.getBody()).block();
        byte[] bytes = new byte[joined.readableByteCount()];
        joined.read(bytes);
        DataBufferUtils.release(joined);
        return bytes;
    }
}
