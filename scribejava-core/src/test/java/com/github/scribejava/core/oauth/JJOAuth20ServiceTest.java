package com.github.scribejava.core.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.java8.Base64;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthConstants;
import java.io.IOException;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

import java.nio.charset.Charset;
import java.util.concurrent.ExecutionException;

public class JJOAuth20ServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final Base64.Encoder base64Encoder = Base64.getEncoder();

    @Test
    public void shouldProduceCorrectScope() throws IOException, InterruptedException, ExecutionException {
        final OAuth20Service service = new ServiceBuilder("your_api_key")
                .apiSecret("your_api_secret")
                .defaultScope("default_scope1")
                .build(new OAuth20ApiUnit());

        final OAuth2AccessToken token = service.getAccessTokenPasswordGrant("user1", "password1", "scope1");
        assertNotNull(token);

        final JsonNode response = OBJECT_MAPPER.readTree(token.getRawResponse());

        assertEquals(OAuth20ServiceUnit.TOKEN, response.get(OAuthConstants.ACCESS_TOKEN).asText());
        assertEquals(OAuth20ServiceUnit.EXPIRES, response.get("expires_in").asInt());

        final String authorize = base64Encoder.encodeToString(
                String.format("%s:%s", service.getApiKey(), service.getApiSecret()).getBytes(Charset.forName("UTF-8")));

        assertEquals(OAuthConstants.BASIC + ' ' + authorize, response.get(OAuthConstants.HEADER).asText());

        assertEquals("scope1", response.get("query-scope").asText());
    }

    @Test
    public void shouldProduceCorrectDefaultScope() throws IOException, InterruptedException, ExecutionException {
        final OAuth20Service service = new ServiceBuilder("your_api_key")
                .apiSecret("your_api_secret")
                .defaultScope("default_scope1")
                .build(new OAuth20ApiUnit());

        final OAuth2AccessToken token = service.getAccessTokenPasswordGrant("user1", "password1");
        assertNotNull(token);

        final JsonNode response = OBJECT_MAPPER.readTree(token.getRawResponse());

        assertEquals(OAuth20ServiceUnit.TOKEN, response.get(OAuthConstants.ACCESS_TOKEN).asText());
        assertEquals(OAuth20ServiceUnit.EXPIRES, response.get("expires_in").asInt());

        final String authorize = base64Encoder.encodeToString(
                String.format("%s:%s", service.getApiKey(), service.getApiSecret()).getBytes(Charset.forName("UTF-8")));

        assertEquals(OAuthConstants.BASIC + ' ' + authorize, response.get(OAuthConstants.HEADER).asText());

        assertEquals("default_scope1", response.get("query-scope").asText());
    }
}
