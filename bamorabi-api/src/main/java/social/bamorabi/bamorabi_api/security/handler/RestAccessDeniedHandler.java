package social.bamorabi.bamorabi_api.security.handler;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

/**
 * Returns a consistent JSON error body (HTTP 403) when an authenticated principal lacks the
 * authority required by the endpoint.
 *
 * <p>Authorization failures are kept distinct from authentication failures: a valid token with
 * insufficient roles produces 403 here and is never downgraded to 401.</p>
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        SecurityErrorResponseWriter.write(response, HttpServletResponse.SC_FORBIDDEN,
                "Forbidden", "Authenticated identity does not have permission to access this resource.",
                request);
    }
}
