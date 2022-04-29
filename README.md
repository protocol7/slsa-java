Software supply chain hack exploring SLSA, sigstore, in-toto, fulcio and rekor.

* Create In-Toto attestation for some Java artifact
  * https://github.com/package-url/purl-spec/
* Create temporary certificiate from Fulcio using OpenID Connect. Based on https://github.com/sigstore/sigstore-java and https://github.com/sigstore/sigstore-maven-plugin.
* [Maybe] Sign JAR using jarsigner
* Upload to Rekor (transparency log)
* Create Maven plugin to do the above
* Enable running Maven build in Github Actions, based on https://github.com/slsa-framework/slsa-github-generator-go.
* Verify signature and attestation.



