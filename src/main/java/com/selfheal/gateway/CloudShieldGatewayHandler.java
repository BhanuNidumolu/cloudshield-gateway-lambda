package com.selfheal.gateway;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPResponse;

import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.regions.Region;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class CloudShieldGatewayHandler implements RequestHandler<APIGatewayV2HTTPEvent, APIGatewayV2HTTPResponse> {

    // ---------------------- CONFIG ----------------------
    private static final String BACKEND_BASE_URL = System.getenv("BACKEND_BASE_URL");
    private static final String JWT_SECRET = System.getenv("JWT_SECRET"); // MUST BE BASE64 ENCODED LIKE SPRING

    private static final DynamoDbClient dynamoDb = DynamoDbClient.builder()
            .region(Region.US_WEST_2)
            .build();

    private static final String RATE_TABLE = "CloudShieldRateLimit";
    private static final int REQUEST_LIMIT = 4;
    private static final int WINDOW_SECONDS = 60;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    // ---------------------- ENTRYPOINT ----------------------
    @Override
    public APIGatewayV2HTTPResponse handleRequest(APIGatewayV2HTTPEvent event, Context context) {
        LambdaLogger log = context.getLogger();

        if (BACKEND_BASE_URL == null || BACKEND_BASE_URL.isBlank()) {
            return respond(500, "CloudShield ERROR: BACKEND_BASE_URL not set");
        }
        if (JWT_SECRET == null || JWT_SECRET.isBlank()) {
            return respond(500, "CloudShield ERROR: JWT_SECRET not configured");
        }
        if (event == null) {
            return respond(400, "Invalid HTTP event");
        }

        String method = event.getRequestContext().getHttp().getMethod();
        String path = event.getRawPath();
        String body = event.getBody();
        Map<String, String> headers = event.getHeaders();

        log.log("Incoming request: " + method + " " + path + "\n");

        boolean isPublicRoute = path.equals("/api/login") || path.equals("/api/register");

        // ---------------------- AUTH + JWT VALIDATION ----------------------
        String authHeader = headers != null ? headers.getOrDefault("authorization", "") : "";
        String clientId = null;

        if (!isPublicRoute) {
            clientId = validateJwt(authHeader, log);
            if (clientId == null) {
                return respond(401, "Invalid or expired token");
            }

            // ---------------------- RATE LIMIT ----------------------
            if (isRateLimited(clientId)) {
                return respond(429, "Rate limit exceeded by CloudShield");
            }
        }

        try {
            // ---------------------- BUILD BACKEND URL ----------------------
            String targetUrl = BACKEND_BASE_URL + path;

            Map<String, String> queryParams = event.getQueryStringParameters();
            if (queryParams != null && !queryParams.isEmpty()) {
                StringBuilder query = new StringBuilder("?");
                queryParams.forEach((k, v) -> query.append(k).append("=").append(v).append("&"));
                targetUrl += query.substring(0, query.length() - 1);
            }

            log.log("Forwarding to backend: " + targetUrl + "\n");

            // ---------------------- BACKEND REQUEST ----------------------
            HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(targetUrl));

            switch (method.toUpperCase()) {
                case "GET" -> builder.GET();
                case "POST" -> builder.POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
                case "PUT" -> builder.PUT(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
                case "DELETE" -> builder.method("DELETE", HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
                default -> builder.method(method, HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
            }

            // ---------------------- SAFE HEADERS ----------------------
            if (headers != null) {
                for (Map.Entry<String, String> h : headers.entrySet()) {
                    String k = h.getKey();
                    String v = h.getValue();
                    if (v == null) continue;

                    // skip restricted headers
                    if (k.equalsIgnoreCase("host") ||
                            k.equalsIgnoreCase("content-length") ||
                            k.equalsIgnoreCase("connection") ||
                            k.equalsIgnoreCase("expect") ||
                            k.equalsIgnoreCase("date") ||
                            k.equalsIgnoreCase("upgrade")) {
                        continue;
                    }

                    builder.header(k, v);
                }
            }

            HttpRequest backendReq = builder.build();
            HttpResponse<String> backendResp = httpClient.send(backendReq, HttpResponse.BodyHandlers.ofString());

            log.log("Backend responded with: " + backendResp.statusCode() + "\n");

            return APIGatewayV2HTTPResponse.builder()
                    .withStatusCode(backendResp.statusCode())
                    .withBody(backendResp.body())
                    .build();

        } catch (Exception e) {
            log.log("CloudShield ERROR: " + e.getMessage() + "\n");
            return respond(502, "CloudShield ERROR: " + e.getMessage());
        }
    }

    // ---------------------- JWT VALIDATION (HS256) ----------------------
    private String validateJwt(String authHeader, LambdaLogger log) {
        try {
            if (authHeader == null || authHeader.isBlank()) return null;
            if (!authHeader.toLowerCase().startsWith("bearer ")) return null;

            String token = authHeader.substring(7).trim();
            String[] parts = token.split("\\.");
            if (parts.length != 3) return null;

            String headerAndPayload = parts[0] + "." + parts[1];
            String signaturePart = parts[2];

            // Decode Base64 KEY (VERY IMPORTANT — matches Spring Boot)
            byte[] keyBytes = Base64.getDecoder().decode(JWT_SECRET);
            SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256");

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] expectedRawSig = mac.doFinal(headerAndPayload.getBytes(StandardCharsets.UTF_8));

            String expectedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedRawSig);

            if (!MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.UTF_8),
                    signaturePart.getBytes(StandardCharsets.UTF_8))) {
                log.log("JWT signature mismatch\n");
                return null;
            }

            // Decode payload
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            JsonNode payload = OBJECT_MAPPER.readTree(payloadJson);

            // Expiry check
            if (payload.has("exp")) {
                long exp = payload.get("exp").asLong();
                long now = Instant.now().getEpochSecond();
                if (exp < now) {
                    log.log("JWT expired\n");
                    return null;
                }
            }

            // Extract username/sub (Spring sets `sub`)
            if (payload.hasNonNull("sub")) return payload.get("sub").asText();

            return null;

        } catch (Exception e) {
            log.log("JWT validation error: " + e.getMessage() + "\n");
            return null;
        }
    }

    // ---------------------- RATE LIMITER ----------------------
    private boolean isRateLimited(String clientId) {
        long now = Instant.now().getEpochSecond();
        long windowStart = now - (now % WINDOW_SECONDS);

        HashMap<String, AttributeValue> key = new HashMap<>();
        key.put("clientId", AttributeValue.builder().s(clientId).build());
        key.put("windowStart", AttributeValue.builder().n(Long.toString(windowStart)).build());

        HashMap<String, AttributeValueUpdate> updates = new HashMap<>();
        updates.put("count", AttributeValueUpdate.builder()
                .value(AttributeValue.builder().n("1").build())
                .action(AttributeAction.ADD)
                .build());

        updates.put("ttl", AttributeValueUpdate.builder()
                .value(AttributeValue.builder().n(Long.toString(now + WINDOW_SECONDS)).build())
                .action(AttributeAction.PUT)
                .build());

        UpdateItemRequest req = UpdateItemRequest.builder()
                .tableName(RATE_TABLE)
                .key(key)
                .attributeUpdates(updates)
                .returnValues(ReturnValue.UPDATED_NEW)
                .build();

        try {
            UpdateItemResponse res = dynamoDb.updateItem(req);
            int count = Integer.parseInt(res.attributes().get("count").n());
            return count > REQUEST_LIMIT;
        } catch (Exception e) {
            return false; // fail open
        }
    }

    private APIGatewayV2HTTPResponse respond(int code, String body) {
        return APIGatewayV2HTTPResponse.builder()
                .withStatusCode(code)
                .withBody(body)
                .build();
    }
}
