package com.github.scribejava.core.oauth2;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

public class JJOAuth2Test {

    @Test
    public void shouldParseResponsee() throws IOException {
        final OAuth2Error tmp = OAuth2Error.INVALID_GRANT;
        assertEquals("invalid_grant", tmp.getErrorString());
        assertEquals(OAuth2Error.INVALID_GRANT, OAuth2Error.INVALID_GRANT);
    }
}
