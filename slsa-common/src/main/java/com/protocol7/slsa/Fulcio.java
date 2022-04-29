package com.protocol7.slsa;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.PemReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Fulcio {
  /** URL of Fulcio instance */
  public static final String PUBLIC_URL = "https://fulcio.sigstore.dev";

  private final HttpTransport httpTransport;
  private final String instanceURL;

  public Fulcio(final HttpTransport httpTransport, final String instanceURL) {
    this.httpTransport = httpTransport;
    this.instanceURL = instanceURL;
  }

  public Fulcio(final HttpTransport httpTransport) {
    this(httpTransport, PUBLIC_URL);
  }

  /**
   * Obtains a X509 code signing certificate signed by the Fulcio instance specified in <code>
   * fulcioInstanceURL</code>.
   *
   * @param signedEmail a base64 encoded String containing the signed email address to associate
   *     with the requested certificate
   * @param pubKey the public key used to verify the signed email address; this key will be included
   *     in the final certificate
   * @param idToken a raw OIDC Identity token specified in JWS format
   * @return The certificate chain including the code signing certificate
   */
  public CertPath getSigningCert(
      final String signedEmail, final PublicKey pubKey, final String idToken)
      throws IOException, CertificateException {
    final String publicKeyB64 = Base64.getEncoder().encodeToString(pubKey.getEncoded());
    final Map<String, Object> fulcioPostContent = new HashMap<>();
    final Map<String, Object> publicKeyContent = new HashMap<>();
    publicKeyContent.put("content", publicKeyB64);
    // TODO: look at signingAlgorithm and set accordingly
    if (pubKey.getAlgorithm().equals("EC")) {
      publicKeyContent.put("algorithm", "ecdsa");
    }

    fulcioPostContent.put("signedEmailAddress", signedEmail);
    fulcioPostContent.put("publicKey", publicKeyContent);

    final JsonHttpContent jsonContent = new JsonHttpContent(new GsonFactory(), fulcioPostContent);
    final ByteArrayOutputStream stream = new ByteArrayOutputStream();
    jsonContent.writeTo(stream);

    final GenericUrl fulcioPostUrl = new GenericUrl(instanceURL + "/api/v1/signingCert");
    final HttpRequest req =
        httpTransport.createRequestFactory().buildPostRequest(fulcioPostUrl, jsonContent);

    req.getHeaders().set("Accept", "application/pem-certificate-chain");
    req.getHeaders().set("Authorization", "Bearer " + idToken);

    // requesting signing certificate
    final HttpResponse resp = req.execute();
    if (resp.getStatusCode() != 201) {
      throw new IOException(
          String.format(
              "bad response from fulcio @ '%s' : %s", fulcioPostUrl, resp.parseAsString()));
    }

    // parsing signing certificate
    final CertificateFactory cf = CertificateFactory.getInstance("X.509");
    final ArrayList<X509Certificate> certList = new ArrayList<>();
    final PemReader pemReader = new PemReader(new InputStreamReader(resp.getContent()));
    while (true) {
      final PemReader.Section section = pemReader.readNextSection();
      if (section == null) {
        break;
      }

      byte[] certBytes = section.getBase64DecodedBytes();
      certList.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes)));
    }

    if (certList.isEmpty()) {
      throw new IOException("no certificates were found in response from Fulcio instance");
    }
    return cf.generateCertPath(certList);
  }
}
