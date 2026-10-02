package com.hkjang.bbmcp.permission;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * GatewayAuthFilter restricts the permission API to the bbmcp gateway.
 *
 * A caller must present the shared secret and a matching HMAC-SHA256 signature
 * over "<timestamp>\n<path>", with the timestamp inside a five minute window.
 * Without a configured secret the API stays closed rather than open, so a
 * half-finished install cannot leak permission data.
 *
 * Configure the secret as a Bitbucket system property, for example in
 * bitbucket.properties:
 *
 *   bbmcp.permission.secret=<same value entered in the bbmcp admin console>
 */
public class GatewayAuthFilter implements Filter {

    private static final String HEADER_TOKEN = "X-BBMCP-Token";
    private static final String HEADER_TIMESTAMP = "X-BBMCP-Timestamp";
    private static final String HEADER_SIGNATURE = "X-BBMCP-Signature";
    private static final long MAX_SKEW_SECONDS = 300L;

    private String secretProperty = "bbmcp.permission.secret";

    @Override
    public void init(FilterConfig filterConfig) {
        String configured = filterConfig.getInitParameter("secret-property");
        if (configured != null && !configured.trim().isEmpty()) {
            secretProperty = configured.trim();
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String secret = System.getProperty(secretProperty);
        if (secret == null || secret.trim().isEmpty()) {
            secret = System.getenv("BBMCP_PERMISSION_SECRET");
        }
        if (secret == null || secret.trim().isEmpty()) {
            deny(httpResponse, "권한 API 비밀값이 설정되지 않았습니다");
            return;
        }

        String token = httpRequest.getHeader(HEADER_TOKEN);
        if (token == null || !constantTimeEquals(secret, token)) {
            deny(httpResponse, "서비스 토큰이 올바르지 않습니다");
            return;
        }

        String timestamp = httpRequest.getHeader(HEADER_TIMESTAMP);
        String signature = httpRequest.getHeader(HEADER_SIGNATURE);
        if (timestamp == null || signature == null) {
            deny(httpResponse, "서명 헤더가 없습니다");
            return;
        }

        long sent;
        try {
            sent = Long.parseLong(timestamp.trim());
        } catch (NumberFormatException e) {
            deny(httpResponse, "타임스탬프 형식이 올바르지 않습니다");
            return;
        }
        long skew = Math.abs((System.currentTimeMillis() / 1000L) - sent);
        if (skew > MAX_SKEW_SECONDS) {
            deny(httpResponse, "타임스탬프가 허용 범위를 벗어났습니다");
            return;
        }

        String path = httpRequest.getRequestURI();
        String contextPath = httpRequest.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }

        String expected = hmacHex(secret, timestamp.trim() + "\n" + path);
        if (!constantTimeEquals(expected, signature.trim())) {
            deny(httpResponse, "서명이 일치하지 않습니다");
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Nothing to release.
    }

    private static void deny(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json; charset=utf-8");
        response.getWriter().write("{\"error\":\"" + message.replace("\"", "'") + "\"}");
    }

    private static String hmacHex(String secret, String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 계산 실패", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
