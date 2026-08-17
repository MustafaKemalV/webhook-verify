package io.github.mustafakemalv.webhookverify.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class CachedBodyHttpServletRequestTest {

    @Test
    void body_can_be_read_more_than_once() throws Exception {
        MockHttpServletRequest original = new MockHttpServletRequest();
        byte[] body = "{\"hello\":\"world\"}".getBytes(StandardCharsets.UTF_8);
        original.setContent(body);

        CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(original);

        byte[] first = cached.getInputStream().readAllBytes();
        byte[] second = cached.getInputStream().readAllBytes();

        assertThat(first).isEqualTo(body);
        assertThat(second).isEqualTo(body);
        assertThat(cached.getCachedBody()).isEqualTo(body);
    }
}
