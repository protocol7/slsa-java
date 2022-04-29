package com.protocol7.slsa.maven;

import com.google.common.collect.Lists;
import com.google.common.io.BaseEncoding;
import com.protocol7.slsa.Fulcio;
import com.protocol7.slsa.OIDC;
import com.protocol7.slsa.Rekor;
import com.protocol7.slsa.Sigstore;
import io.github.intoto.dsse.helpers.SimpleECDSASigner;
import io.github.intoto.exceptions.InvalidModelException;
import io.github.intoto.helpers.IntotoHelper;
import io.github.intoto.models.DigestSetAlgorithmType;
import io.github.intoto.models.Statement;
import io.github.intoto.models.Subject;
import io.github.intoto.slsa.models.*;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.manager.ArtifactHandlerManager;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static com.protocol7.slsa.Sigstore.getHttpTransport;

@Mojo(name = "attest", defaultPhase = LifecyclePhase.PACKAGE)
public class Attest extends AbstractMojo {

    /**
     * Reference to maven project; will be used to find JAR file to be signed unless
     * specified in input-jar
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    @Parameter(defaultValue = "${session.request.startTime}", readonly = true)
    private Date timestamp;

    @Parameter(defaultValue = "${project.build.directory}", readonly = true)
    private File outputDirectory;

    @Parameter(defaultValue = "${settings.localRepository}", readonly = true)
    private File localRepo;

    @Component
    private ArtifactHandlerManager artifactHandlerManager;

    @Parameter(property = "builder", defaultValue = "${user.name}")
    private String builder;

    private String sha256File(final File file) throws IOException, NoSuchAlgorithmException {
        final byte[] b = Files.readAllBytes(file.toPath());
        return BaseEncoding.base16().lowerCase().encode(MessageDigest.getInstance("SHA-256").digest(b));
    }

    @Override
    public void execute() throws MojoFailureException {

        final List<Subject> subjects = new ArrayList<>();
        for (final File file : Lists.newArrayList(project.getFile(), project.getArtifact().getFile())) {
            try {

                final Subject subject=new Subject();
                subject.setName(file.getName());
                subject.setDigest(
                        Map.of(
                                DigestSetAlgorithmType.SHA256.toString(),
                                sha256File(file)));

                subjects.add(subject);

            } catch (IOException | NoSuchAlgorithmException e) {
                throw new MojoFailureException("Failed to hash artifact", e);
            }
        }

        final Provenance provenance = new Provenance();
        final Builder builder = new Builder();
        builder.setId(this.builder);

        provenance.setBuilder(builder);

        final Metadata metadata = new Metadata();
        final Completeness completeness = new Completeness();
        completeness.setArguments(false);
        completeness.setEnvironment(false);
        completeness.setMaterials(true);

        metadata.setBuildStartedOn(timestamp.toInstant().atOffset(ZoneOffset.UTC));

        metadata.setCompleteness(completeness);

        final List<Material> materials = new ArrayList<>();
        for (final Dependency dependency : project.getDependencies()) {
            final Material material = new Material();
            // https://github.com/package-url/purl-spec/
            material.setUri("pkg:maven/" + dependency.getGroupId() + "/" + dependency.getArtifactId() + "@" + dependency.getVersion());

            // add digest for dependency
            // TODO what's a better way of doing this, that also resolves the dependency if needed
            final File groupIdDir = new File(localRepo, dependency.getGroupId().replace('.', '/'));
            final File artifactFile = new File(groupIdDir, dependency.getArtifactId() + "/" + dependency.getVersion() + "/" + dependency.getArtifactId() + "-" + dependency.getVersion() + "." + dependency.getType());

            try {
                material.setDigest(
                        Map.of(
                                DigestSetAlgorithmType.SHA256.toString(),
                                sha256File(artifactFile)));
            } catch (IOException | NoSuchAlgorithmException e) {
                throw new MojoFailureException("Failed to hash dependency", e);
            }

            materials.add(material);
        }
        provenance.setMaterials(materials);

        provenance.setMetadata(metadata);

        final Statement statement = new Statement();
        statement.setSubject(subjects);
        statement.setPredicate(provenance);

        // TODO allow URL parameters to be configured
        final OIDC oidc = new OIDC(getHttpTransport());
        final Fulcio fulcio = new Fulcio(getHttpTransport());
        final Rekor rekor = new Rekor(getHttpTransport());

        try {
            // OIDC dance to get signing email
            final OIDC.IDTokenResult idToken = oidc.getIDToken();

            final KeyPair keyPair = Sigstore.generateKeyPair(Sigstore.SIGNING_ALGORITHM, Sigstore.SIGNING_ALGORITHM_SPEC);

            // sign email address with private key
            final String signedEmail = Sigstore.signEmailAddress(idToken.getEmailAddress(), keyPair.getPrivate());

            // push to fulcio, get signing cert chain
            final CertPath certs = fulcio.getSigningCert(signedEmail, keyPair.getPublic(), idToken.getIdToken());

            // TODO wrap signer with private key and signing cert?

            // TODO what should keyId be?
            final SimpleECDSASigner signer = new SimpleECDSASigner(keyPair.getPrivate(), "keyid");

            final String envelope = IntotoHelper.produceIntotoEnvelopeAsJson(statement, signer, true);

            getLog().info("Attestation: " + envelope);

            final String filePrefix = project.getArtifactId() + "-" + project.getVersion();
            final File attestFile = new File(outputDirectory, filePrefix + ".attestation.json");
            Files.writeString(attestFile.toPath(), envelope);

            final File certFile = new File(outputDirectory, filePrefix + ".attestation.pem");
            Sigstore.writeSigningCertToFile(certs, certFile);

            // upload to rekor transparency log
            rekor.submitInToto(envelope, keyPair.getPublic());

            // attach artifacts
            final Artifact jsonArtifact = new DefaultArtifact(project.getArtifact().getGroupId(), project.getArtifact().getArtifactId(), project.getArtifact().getVersion(), null, "attestion-json", null, artifactHandlerManager.getArtifactHandler("attestion-json"));
            jsonArtifact.setFile(attestFile);
            project.addAttachedArtifact(jsonArtifact);

            final Artifact certsArtifact = new DefaultArtifact(project.getArtifact().getGroupId(), project.getArtifact().getArtifactId(), project.getArtifact().getVersion(), null, "attestion-certs", null, artifactHandlerManager.getArtifactHandler("attestion-certs"));
            certsArtifact.setFile(certFile);
            project.addAttachedArtifact(certsArtifact);

        } catch (NullPointerException | InvalidModelException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | SignatureException | InvalidKeyException | IOException | CertificateException e) {
            e.printStackTrace();
            throw new MojoFailureException("Failed to sign attest", e);
        }
    }
}
