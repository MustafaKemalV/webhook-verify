package io.github.mustafakemalv.webhookverify.webflux;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * A reactive request whose body has been read once into a byte array and can be replayed. The body
 * is joined into a single buffer, copied out, and the buffer released to avoid leaks; every
 * {@link #getBody()} then serves a fresh buffer over the cached bytes so both the signature check
 * and the downstream controller can read it.
 */
public class CachedBodyServerHttpRequest extends ServerHttpRequestDecorator {

    private final byte[] cachedBody;
    private final DataBufferFactory bufferFactory;

    private CachedBodyServerHttpRequest(ServerHttpRequest delegate, byte[] cachedBody,
            DataBufferFactory bufferFactory) {
        super(delegate);
        this.cachedBody = cachedBody;
        this.bufferFactory = bufferFactory;
    }

    /**
     * Reads the exchange's request body once (joining all buffers and releasing them) and returns a
     * decorator that replays the captured bytes on every read.
     */
    public static Mono<CachedBodyServerHttpRequest> capture(ServerWebExchange exchange) {
        ServerHttpRequest request = exchange.getRequest();
        DataBufferFactory factory = exchange.getResponse().bufferFactory();
        return DataBufferUtils.join(request.getBody())
                .map(joined -> {
                    byte[] bytes = new byte[joined.readableByteCount()];
                    joined.read(bytes);
                    DataBufferUtils.release(joined);
                    return new CachedBodyServerHttpRequest(request, bytes, factory);
                })
                .defaultIfEmpty(new CachedBodyServerHttpRequest(request, new byte[0], factory));
    }

    /** The captured raw request body. */
    public byte[] getCachedBody() {
        return cachedBody;
    }

    @Override
    public Flux<DataBuffer> getBody() {
        return Flux.defer(() -> Flux.just(bufferFactory.wrap(cachedBody)));
    }
}
