package test.unit.be.fedict.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.BelgianTrustValidatorFactory;
import be.fedict.trust.TrustValidator;
import be.fedict.trust.linker.CustomCertSignValidator;

public class BelgiumTrustValidatorTest {

    final String[] pemCertificateChainWithIssues = new String[] {
            "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" };

    final String[] pemCertificateChainLiesje = new String[] {
            "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"
    };

    final String[] pemCertificateWithNewIssues = new String[]{
            "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"
    };

    final String citizenCertificatePEM = "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";
    final String failingOCSPResponderCertificatePEM = "MIIEjjCCAnegAwIBAgILBAAAAAABZ6L2IugwDQYJKoZIhvcNAQELBQAwZDELMAkGA1UEBhMCQkUxETAPBgNVBAcTCEJydXNzZWxzMRwwGgYDVQQKExNDZXJ0aXBvc3QgTi5WLi9TLkEuMRMwEQYDVQQDEwpDaXRpemVuIENBMQ8wDQYDVQQFEwYyMDE3MjgwHhcNMTgxMjEwMTEwMDAwWhcNMjAwMTI5MTEwMDAwWjAuMR8wHQYDVQQDExZCZWxnaXVtIE9DU1AgUmVzcG9uZGVyMQswCQYDVQQGEwJCRTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMFqL3rfh0dl60mIFlMhwnfEMzEcSw+8FknhL5423GgrFOb3//q6sAEdB1d2ei6GhKwVMdLuoq08nyLLLq4RcVj0lL87ejerLxHLxy1/VwJZo2DnOsJnqEv5RPkqGmaNwtiu1cU8Vk0rkNBPhWhyRkwLlub6ik+U98hMeYz+C2sY7uZuUm9wQULeijueTmjLdcE7FhiYDjjiCKEpysvTqhm2hfcosHWJv6/8HmeFPIizsGTTmzjO8apNlxaPOcsuF38uaDVcPekNUPObd5eTvkDVuuweZ9X8Qu7dKXaiCOJM+gSukepqkqcIfPXrPIPWQ6suHjgmpJtwKSnYP+q1HBUCAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFMqfkpTDFXVRSnzwBhaGop0YBMGmMA8GCSsGAQUFBzABBQQCBQAwHQYDVR0OBBYEFJ1g+3FNXsIY6d5zekiXPNF7ous0MBMGA1UdJQQMMAoGCCsGAQUFBwMJMA0GCSqGSIb3DQEBCwUAA4ICAADDSp11FvCgMDKkKfPhvNJ1bUJx6GsSTpYQMgabT8qjiKHC+xdsXDOhFoQdZIZ1jJH61E02WD6awaJm/CQ1JC/oIMKnNqGz5nOLk4dMAqXbTFNyLOUF3BWubV8btwsDWxkNwQBSjSnEwykY2AuaZKWrSV+BhF0zYve0pXbFRrUCj0bElBchAbs3wJyhTbY6yzW+qHFGF+iXdzsDbPrRyfWg7URrtbDhLCXJfQbx8mlHwYnuI5Fe/d8XBAg92NqrEQA0OOe2o8IwDABvOuHB1CDn16lhyFrsi0AbSf/zuNQYqx5/mzSwTPUrtN5MJPWlA9ovJo8P17CYGC8oIC2rqahCEY3v5SSdwS9vkT4uOxci7RPQbFoQTJjevPiNm3GIlBOTMiEC+AAfMG2l1Jx/84nWoxro2siDPJfqsYcVoGjnMiLWztNZoKDuD1ZV2DidQZPInQxVF6J/CU3HiiqN1dne2Ecr6eWIjLHp3jc0h01O/5XdU5tXqoeEv8dHcvUNRtKcIzEovbH4Q6swWcISlpVBdd8mi5PlKAEu+1No2bO/mfyhoDeNlovFFDp2mljhEvUEKbnmKDrJaijlsnW9QybmhFDCuab9qGpLHNaONgnhD6KpiN6bqpcL5FGk/z97XmQEg723wb5JmWdpZOtOytLkX6CY2gusR1OOBPk15PV3";

	@BeforeEach
    public void setup(){
        Security.addProvider(new BouncyCastleProvider());
    }

    private List<X509Certificate> loadCertificateChain(final String[] base64EncodedPEMs) throws Exception{
        final List<X509Certificate> certificateChain = new ArrayList<>();
        for (final String pemCertificateEncoded : base64EncodedPEMs) {
            final X509Certificate x509Certificate = loadCertificate(pemCertificateEncoded);
            certificateChain.add(x509Certificate);
        }
        return  certificateChain;
    }

    private X509Certificate loadCertificate(final String pemCertificateEncoded) throws Exception {
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        final byte[] pemCertificate = Base64.getDecoder().decode(pemCertificateEncoded);
        ByteArrayInputStream certificateInputStream = null;
        final X509Certificate x509Certificate;

        try {
            certificateInputStream = new ByteArrayInputStream(pemCertificate);
            x509Certificate = (X509Certificate) certificateFactory.generateCertificate(certificateInputStream);
        } finally {
            {
                IOUtils.closeQuietly(certificateInputStream);
            }
        }

        return x509Certificate;
    }

    @Test
    public void testBelgianTrustValidator_CertificateWithIssues() throws Exception {
        final List<X509Certificate> certificateChain = loadCertificateChain(pemCertificateChainWithIssues);
        validateTrust(certificateChain);
    }

    @Test
    public void testBelgianTrustValidator_CertificateWithNewIssues() throws Exception {
        final List<X509Certificate> certificateChain = loadCertificateChain(pemCertificateWithNewIssues);
        validateTrust(certificateChain);
    }

    @Test
    public void testBelgianTrustValidator_CertificateLiesje() throws Exception {
        final List<X509Certificate> certificateChain = loadCertificateChain(pemCertificateChainLiesje);
        validateTrust(certificateChain);

    }

    @Test
    public void testFailingOCSPResponderCertificate() throws Exception {
        final X509Certificate failingOCSPCertificate = loadCertificate(failingOCSPResponderCertificatePEM);
        final X509Certificate citizenCertificate = loadCertificate(citizenCertificatePEM);

        try {
            failingOCSPCertificate.verify(citizenCertificate.getPublicKey());
        } catch (final SignatureException e) {
            assertEquals(e.getMessage(), "Signature length not correct: got 511 but was expecting 512");
        }
    }

    @Test
    public void testFailingOCSPResponderCertificate_verifyWithPKCS1Padding() throws Exception {
        final X509Certificate failingOCSPCertificate = loadCertificate(failingOCSPResponderCertificatePEM);
        final X509Certificate citizenCertificate = loadCertificate(citizenCertificatePEM);

        CustomCertSignValidator.verify(failingOCSPCertificate, citizenCertificate);
    }

    private void validateTrust(final List<X509Certificate> certificateChain) throws Exception{
        final TrustValidator trustValidator = BelgianTrustValidatorFactory.createTrustValidator();
        trustValidator.isTrusted(certificateChain);
    }

}
