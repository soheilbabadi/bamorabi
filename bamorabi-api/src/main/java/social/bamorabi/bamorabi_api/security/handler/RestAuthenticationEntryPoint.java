package social.bamorabi.bamorabi_api.security.handler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Returns a consistent JSON error body (HTTP 401) whenever a request arrives without valid
 * authentication: missing, malformed, expired or otherwise invalid bearer tokens.
 *
 * <p>The message is generic on purpose — it never echoes token contents or internal exception
 * details. A standard {@code WWW-Authenticate: Bearer} challenge is added, optionally carrying the
 * OAuth2 {@code error} hint (for example {@code error="invalid_token"}) that Spring Security has
 * already computed for the failed request.</p>
 */
@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // 401 always means "authentication missing or invalid" — never an authorization failure.
        SecurityErrorResponseWriter.write(response, HttpServletResponse.SC_UNAUTHORIZED,
                "Unauthorized", "Authentication required: the access token is missing, malformed or invalid.",
                request);
        writeBearerChallenge(request, response);
    }

    private void writeBearerChallenge(HttpServletRequest request, HttpServletResponse response) {
        String challenge = "Bearer";
        String errorHint = resolveErrorHint(request);
        if (errorHint != null) {
            challenge += " realm=\"api\", error=\"" + sanitize(errorHint) + "\"";
        }
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge);
    }

    /**
     * Extracts the OAuth2 error description (e.g. {@code invalid_token}) from the bearer token
     * previously stored by Spring Security as Basic-auth-encoded credentials, if present.
     */
    private String resolveErrorHint(HttpServletRequest request) {
        Object credentials = request.getAttribute(HttpHeaders.AUTHORIZATION);
        if (!(credentials instanceof String encoded) || !StringUtils.hasText(encoded)) {
            return null;
        }
        try {
            String value = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int separator = value.indexOf(':');
            String detail = separator >= 0 ? value.substring(separator + 1) : value;
            return StringUtils.hasText(detail) ? detail : null;
        } catch (IllegalArgumentException e) {
            // Undecodable leftovers are irrelevant to the client; respond with a plain challenge.
            return null;
        }
    }

    /** Keeps the header free of quote injection and control characters. */
    private String sanitize(String value) {
        return value.replaceAll("[\"\\\\\\p{Cntrl}]", "");
    }
}
