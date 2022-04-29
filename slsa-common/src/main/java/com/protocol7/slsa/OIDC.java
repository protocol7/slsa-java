package com.protocol7.slsa;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;
import com.google.gson.Gson;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.util.List;
import java.util.Map;

public class OIDC {

    /**
     * Client ID for OIDC Identity Provider
     */
    public static final String DEFAULT_OIDC_CLIENT_ID = "sigstore";
    /**
     * URL of OIDC Identity Provider Authorization endpoint
     */
    public static final String OIDC_AUTH_URL = "https://oauth2.sigstore.dev/auth/auth";
    /**
     * URL of OIDC Identity Provider Token endpoint
     */
    public static final String OIDC_TOKEN_URL = "https://oauth2.sigstore.dev/auth/token";

    /**
     * URL of OIDC Identity Provider Device Code endpoint
     */
    private static final String OIDC_DEVICE_CODE_URL = "https://oauth2.sigstore.dev/auth/device/code";


    private final HttpTransport httpTransport;
    private final boolean oidcDeviceCodeFlow;
    private final String authUrl;
    private final String tokenUrl;
    private final String token;
    private final String clientId;

    public OIDC(final HttpTransport httpTransport, String authUrl, String tokenUrl, String clientId) {
        this.httpTransport = httpTransport;
        this.oidcDeviceCodeFlow = false;
        this.authUrl = authUrl;
        this.tokenUrl = tokenUrl;
        this.token = null;
        this.clientId = clientId;
    }

    public OIDC(final HttpTransport httpTransport, String tokenUrl, String token) {
        this.httpTransport = httpTransport;
        this.oidcDeviceCodeFlow = true;
        this.authUrl = null;
        this.tokenUrl = tokenUrl;
        this.token = token;
        this.clientId = null;
    }

    public OIDC(final HttpTransport httpTransport) {
        this(httpTransport, OIDC_AUTH_URL, OIDC_TOKEN_URL, DEFAULT_OIDC_CLIENT_ID);
    }

    public static class IDTokenResult {
        private final String idToken;
        private final String emailAddress;

        public IDTokenResult(final String idToken, final String emailAddress) {
            this.idToken = idToken;
            this.emailAddress = emailAddress;
        }

        public String getIdToken() {
            return idToken;
        }

        public String getActor() {
            return emailAddress;
        }
    }

    /**
     * Obtains an OpenID Connect Identity Token from the OIDC provider specified in <code>oidcAuthURL</code>
     *
     * @return the ID token String (in JWS format)
     */
    public IDTokenResult getIDToken() throws IOException {
        final JsonFactory jsonFactory = new GsonFactory();
        final DataStoreFactory memStoreFactory = new MemoryDataStoreFactory();

        final String idTokenKey = "id_token";

        final String idTokenString;
        final String actor;
        if (!oidcDeviceCodeFlow) {
            final AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
                    BearerToken.authorizationHeaderAccessMethod(), httpTransport, jsonFactory,
                    new GenericUrl(tokenUrl), new ClientParametersAuthentication(clientId, null),
                    clientId, authUrl)
                    .enablePKCE()
                    .setScopes(List.of("openid", "email"))
                    .setCredentialCreatedListener((credential, tokenResponse) -> memStoreFactory.getDataStore("user").set(idTokenKey,
                            tokenResponse.get(idTokenKey).toString()));

            final AuthorizationCodeInstalledApp app = new AuthorizationCodeInstalledApp(flowBuilder.build(),
                    new LocalServerReceiver());
            app.authorize("user");

            idTokenString = (String) memStoreFactory.getDataStore("user").get(idTokenKey);

            final IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
            final IdToken parsedIdToken = IdToken.parse(jsonFactory, idTokenString);
            if (!idTokenVerifier.verify(parsedIdToken)) {
                throw new InvalidObjectException("id token could not be verified");
            }

            actor = (String) parsedIdToken.getPayload().get("email");
            final Boolean emailVerified = (Boolean) parsedIdToken.getPayload().get("email_verified");

            if (Boolean.FALSE.equals(emailVerified)) {
                throw new InvalidObjectException(
                        String.format("identity provider '%s' reports email address '%s' has not been verified",
                                parsedIdToken.getPayload().getIssuer(), actor));
            }
        } else {
            final HttpResponse response = httpTransport.createRequestFactory()
                    .buildGetRequest(new GenericUrl(tokenUrl + "&audience=sigstore"))
                    .setHeaders(new HttpHeaders().set("Authorization", "Bearer " + token))
                    .execute();

            final Gson g = new Gson();
            final Map map = g.fromJson(response.parseAsString(), Map.class);

            idTokenString = (String) map.get("value");

            final IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
            final IdToken parsedIdToken = IdToken.parse(jsonFactory, idTokenString);
            if (!idTokenVerifier.verify(parsedIdToken)) {
                throw new InvalidObjectException("id token could not be verified");
            }

            actor = (String) parsedIdToken.getPayload().get("sub");
        }
        // TODO: add device code flow support

        return new IDTokenResult(idTokenString, actor);
    }
}
