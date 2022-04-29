package com.protocol7.slsa;

import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.zip.ZipFile;
import jdk.security.jarsigner.JarSigner;
import org.apache.commons.io.output.TeeOutputStream;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.shared.jarsigner.JarSignerUtil;

public class Sigstore {

  private final String signerName = "sigstore";
  /** Signing algorithm to be used; default is ECDSA */
  public static final String SIGNING_ALGORITHM = "EC";
  /** Signing algorithm specification to be used; default is secp256r1 */
  public static final String SIGNING_ALGORITHM_SPEC = "secp256r1";

  /**
   * Returns a new ephemeral keypair according to the plugin parameters
   *
   * @param signingAlgorithm an absolute URL giving the base location of the image
   * @param signingAlgorithmSpec the location of the image, relative to the url argument
   * @return the public and private keypair
   */
  public static KeyPair generateKeyPair(
      final String signingAlgorithm, final String signingAlgorithmSpec)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    final KeyPairGenerator kpg = KeyPairGenerator.getInstance(signingAlgorithm);
    final AlgorithmParameterSpec aps;
    switch (signingAlgorithm) {
      case "EC":
        aps = new ECGenParameterSpec(signingAlgorithmSpec);
        break;
      default:
        throw new IllegalArgumentException(
            String.format(
                "unable to create signing algorithm spec for signing algorithm %s",
                signingAlgorithm));
    }

    kpg.initialize(aps, new SecureRandom());
    return kpg.generateKeyPair();
  }

  /**
   * Signs the provided actor using the provided private key
   *
   * @param actor The actor identity, e.g. email address, to sign
   * @param privKey The private key used to sign
   * @return base64 encoded String containing the signature for the provided actor
   */
  public static String signActor(final String actor, final PrivateKey privKey)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    if (privKey == null) {
      throw new IllegalArgumentException("private key must be specified");
    }
    if (actor == null) {
      throw new IllegalArgumentException("actor must not be null");
    }

    // signing actor '%s' as proof of possession of private key
    final Signature sig;
    switch (privKey.getAlgorithm()) {
      case "EC":
        sig = Signature.getInstance("SHA256withECDSA");
        break;
      default:
        throw new NoSuchAlgorithmException(
            String.format(
                "unable to generate signature for signing algorithm %s", SIGNING_ALGORITHM));
    }
    sig.initSign(privKey);
    sig.update(actor.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(sig.sign());
  }

  /**
   * Generates an HTTP Transport according to the requested SSL verification settings
   *
   * @return transport object with SSL verification enabled/disabled per the plugin parameter <code>
   *     sslVerification</code>
   */
  public static HttpTransport getHttpTransport() {
    final HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
    return new ApacheHttpTransport(hcb.build());
  }

  /**
   * Signs a JAR file with {@code jarsigner} using the private key; the provided certificate chain
   * will be included in the signed JAR file
   *
   * @param privKey the private key that should be used to sign the JAR file
   * @param certs The certificate chain including the code signing certificate which can be used to
   *     verify the signature
   * @return The signed JAR file in byte array
   */
  private byte[] signJarFile(
      final File jarToSign,
      final File outputJarFile,
      final PrivateKey privKey,
      final CertPath certs)
      throws URISyntaxException, IOException, NoSuchAlgorithmException {
    final ByteArrayOutputStream memOut = new ByteArrayOutputStream();

    final JarSigner.Builder jsb =
        new JarSigner.Builder(privKey, certs)
            .digestAlgorithm("SHA-256")
            .signatureAlgorithm("SHA256withECDSA")
            .setProperty("internalsf", "true")
            .signerName(signerName)
            .tsa(new URI(Rekor.TSA_URL));

    final JarSigner js = jsb.build();

    try (final ZipFile in = new ZipFile(jarToSign);
        final FileOutputStream jarOut = new FileOutputStream(outputJarFile);
        final TeeOutputStream tee = new TeeOutputStream(jarOut, memOut)) {
      js.sign(in, tee);

      if (!JarSignerUtil.isArchiveSigned(outputJarFile)) {
        throw new VerifyError(
            "JAR signing verification failed: archive does not contain signature");
      }
    }

    return memOut.toByteArray();
  }

  /**
   * Writes the code signing certificate to a file
   *
   * @param certs The certificate chain including the code signing certificate which can be used to
   *     verify the signature
   * @param outputSigningCert The file where the code signing cert should be written to
   */
  public static void writeSigningCertToFile(CertPath certs, File outputSigningCert)
      throws IOException, CertificateEncodingException {
    final String lineSeparator = System.getProperty("line.separator");

    final Base64.Encoder encoder = Base64.getMimeEncoder(64, lineSeparator.getBytes());
    // we only write the first one, not the entire chain
    byte[] rawCrtText = certs.getCertificates().get(0).getEncoded();
    final String encodedCertText = new String(encoder.encode(rawCrtText));

    final String prettifiedCert =
        "-----BEGIN CERTIFICATE-----"
            + lineSeparator
            + encodedCertText
            + lineSeparator
            + "-----END CERTIFICATE-----";

    try (final FileWriter fw = new FileWriter(outputSigningCert)) {
      fw.write(prettifiedCert);
    }
  }
}
