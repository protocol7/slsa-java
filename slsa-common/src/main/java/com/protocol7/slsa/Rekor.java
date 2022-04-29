package com.protocol7.slsa;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.gson.GsonFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Rekor {

  /** URL of Rekor instance */
  public static final String PUBLIC_URL = "https://rekor.sigstore.dev";

  /** URL of Trusted Timestamp Authority (RFC3161 compliant) */
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
   * @return The URL where the entry in the transparency log can be seen for this signature/key
   *     combination
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
    final String pem =
        "-----BEGIN PUBLIC KEY-----\n"
            + Base64.getEncoder().encodeToString(publicKey.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";

    final Map<String, Object> specContent = new HashMap<>();

    final Map<String, Object> content = new HashMap<>();
    content.put("envelope", envelope);

    specContent.put("content", content);
    specContent.put(
        "publicKey", Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8)));

    return submit(specContent, "intoto", "0.0.1");
  }

  private String submit(
      final Map<String, Object> specContent, final String kind, final String apiVersion)
      throws IOException {
    final Map<String, Object> rekorPostContent = new HashMap<>();
    rekorPostContent.put("kind", kind);
    rekorPostContent.put("apiVersion", apiVersion);
    rekorPostContent.put("spec", specContent);

    final JsonHttpContent rekorJsonContent =
        new JsonHttpContent(new GsonFactory(), rekorPostContent);
    final ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
    rekorJsonContent.writeTo(rekorStream);

    final GenericUrl rekorPostUrl = new GenericUrl(instanceURL + "/api/v1/log/entries");
    final HttpRequest rekorReq =
        httpTransport.createRequestFactory().buildPostRequest(rekorPostUrl, rekorJsonContent);

    rekorReq.getHeaders().set("Accept", "application/json");
    rekorReq.getHeaders().set("Content-Type", "application/json");

    final HttpResponse rekorResp = rekorReq.execute();
    if (rekorResp.getStatusCode() != 201) {
      throw new IOException("bad response from rekor: " + rekorResp.parseAsString());
    }

    final URL rekorEntryUrl = new URL(new URL(instanceURL), rekorResp.getHeaders().getLocation());

    return rekorEntryUrl.toString();
  }
}
