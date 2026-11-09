package social.bamorabi.bamorabi_api.security.handler;

import java.io.IOException;
import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.tracing.Span;
import io.micrometer.tracing.TraceContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

/**
 * Renders the consistent JSON error envelope shared by the security handlers.
 *
 * <p>The payload contains only what a client needs to understand and correlate the failure:
 * timestamp, status, error, message, path and (when tracing is active) a traceId. It never
 * exposes JWT contents, exception details or stack traces.</p>
 */
final class SecurityErrorResponseWriter {

    /** Plain Jackson mapper: security error rendering must not depend on application-wide config. */
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecurityErrorResponseWriter() {
    }

    static void write(HttpServletResponse response, int status, String error, String message,
                      HttpServletRequest request) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        ErrorBody body = new ErrorBody(
                Instant.now().toString(),
                status,
                error,
                StringUtils.hasText(message) ? message : "No further details available.",
                request.getRequestURI(),
                currentTraceId());
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(MAPPER.writeValueAsString(body));
    }

    /** Immutable JSON error payload. {@code traceId} is omitted when no trace context is active. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record ErrorBody(String timestamp, int status, String error, String message, String path, String traceId) {
    }

    /** Correlation id from the active Micrometer Tracing / OpenTelemetry span, or {@code null}. */
    private static String currentTraceId() {
        Span span = Span.current();
        if (span != null && span.isRecording()) {
            TraceContext context = span.context();
            if (context != null && StringUtils.hasText(context.traceId())) {
                return context.traceId();
            }
        }
        return null;
    }
}
