package com.protocol7.slsa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.gson.GsonFactory;
import com.google.common.io.BaseEncoding;
import io.github.intoto.dsse.helpers.SimpleECDSASigner;
import io.github.intoto.dsse.models.IntotoEnvelope;
import io.github.intoto.exceptions.InvalidModelException;
import io.github.intoto.helpers.IntotoHelper;
import io.github.intoto.models.DigestSetAlgorithmType;
import io.github.intoto.models.Statement;
import io.github.intoto.models.Subject;
import io.github.intoto.slsa.models.Builder;
import io.github.intoto.slsa.models.Completeness;
import io.github.intoto.slsa.models.Metadata;
import io.github.intoto.slsa.models.Provenance;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Rekor {

    public static void main(String[] args) throws InvalidModelException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        Subject subject=new Subject();
        subject.setName("curl-7.72.0.tar.bz2");
        subject.setDigest(
                Map.of(
                        DigestSetAlgorithmType.SHA256.toString(),
                        "d4d5899a3868fbb6ae1856c3e55a32ce35913de3956d1973caccd37bd0174fa2"));

        Provenance provenance = new Provenance();
        Builder builder = new Builder();
        builder.setId("my builder");
        provenance.setBuilder(builder);

        Metadata metadata = new Metadata();
        Completeness completeness = new Completeness();
        completeness.setArguments(true);
        completeness.setEnvironment(true);
        completeness.setMaterials(true);

        metadata.setCompleteness(completeness);

        provenance.setMetadata(metadata);

        Statement statement=new Statement();
        statement.setSubject(List.of(subject));
        statement.setPredicate(provenance);

        KeyPair keyPair = Sigstore.generateKeyPair(Sigstore.SIGNING_ALGORITHM, Sigstore.SIGNING_ALGORITHM_SPEC);

        SimpleECDSASigner signer = new SimpleECDSASigner(keyPair.getPrivate(), "keyid");

        String json = IntotoHelper.produceIntotoEnvelopeAsJson(statement,signer, true);

        Rekor rekor = new Rekor(Sigstore.getHttpTransport());

        String url = rekor.submitInToto(json, keyPair.getPublic());

        System.out.println(url);
    }

    /**
     * URL of Rekor instance
     */
    public static final String PUBLIC_URL = "https://rekor.sigstore.dev";

    /**
     * URL of Trusted Timestamp Authority (RFC3161 compliant)
     */
    public static final String TSA_URL = "https://rekor.sigstore.dev/api/v1/timestamp";

    private final HttpTransport httpTransport;
    private final String instanceURL;

    public Rekor(final HttpTransport httpTransport, final String instanceURL) {
        this.httpTransport = httpTransport;
        this.instanceURL = instanceURL;
    }

    public Rekor(final HttpTransport httpTransport) {
        this(httpTransport, PUBLIC_URL);
    }

    /**
     * Submits the jarsigned JAR to a Rekor transparency log, with rekor {@code jar} type
     *
     * @param jarBytes The signed JAR file in a byte array
     * @return The URL where the entry in the transparency log can be seen for this signature/key combination
     */
    public String submitSignedJar(final byte[] jarBytes) throws IOException {
        final String jarB64 = Base64.getEncoder().encodeToString(jarBytes);

        final Map<String, Object> specContent = new HashMap<>();
        final Map<String, Object> archiveContent = new HashMap<>();
        archiveContent.put("content", jarB64); // could be url + hash instead
        specContent.put("archive", archiveContent);

        // https://github.com/sigstore/rekor/blob/main/pkg/types/jar/v0.0.1/jar_v0_0_1_schema.json
        return submit(specContent, "jar", "0.0.1");
    }

    public String submitInToto(final String envelope, final PublicKey publicKey) throws IOException {
        final String pem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n-----END PUBLIC KEY-----\n";

        final Map<String, Object> specContent = new HashMap<>();

        final Map<String, Object> content = new HashMap<>();
        content.put("envelope", envelope);

        specContent.put("content", content);
        specContent.put("publicKey", Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8)));

        return submit(specContent, "intoto", "0.0.1");
    }

    private String submit(final Map<String, Object> specContent, final String kind, final String apiVersion) throws IOException {
        final Map<String, Object> rekorPostContent = new HashMap<>();
        rekorPostContent.put("kind", kind);
        rekorPostContent.put("apiVersion", apiVersion);
        rekorPostContent.put("spec", specContent);

        final JsonHttpContent rekorJsonContent = new JsonHttpContent(new GsonFactory(), rekorPostContent);
        final ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
        rekorJsonContent.writeTo(rekorStream);

        final GenericUrl rekorPostUrl = new GenericUrl(instanceURL + "/api/v1/log/entries");
        final HttpRequest rekorReq = httpTransport.createRequestFactory().buildPostRequest(rekorPostUrl, rekorJsonContent);

        rekorReq.getHeaders().set("Accept", "application/json");
        rekorReq.getHeaders().set("Content-Type", "application/json");

        final HttpResponse rekorResp = rekorReq.execute();
        if (rekorResp.getStatusCode() != 201) {
            throw new IOException("bad response from rekor: " + rekorResp.parseAsString());
        }

        final URL rekorEntryUrl = new URL(new URL(instanceURL), rekorResp.getHeaders().getLocation());
        System.out.println(String.format("Created entry in transparency log for JAR @ '%s'", rekorEntryUrl));
        return rekorEntryUrl.toString();
    }

}
