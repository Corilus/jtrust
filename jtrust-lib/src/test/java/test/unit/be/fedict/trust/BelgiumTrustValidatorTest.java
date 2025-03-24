package test.unit.be.fedict.trust;

import static org.junit.jupiter.api.Assertions.*;

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

    final String[] pemCertificateWithNewIssues = new String[]{
            "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"
    };

    final String[] pemCertificateChainThibault = new String[] {
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
    public void testBelgianTrustValidator_CertificateWithNewIssues() throws Exception {
        final List<X509Certificate> certificateChain = loadCertificateChain(pemCertificateWithNewIssues);
        validateTrust(certificateChain);
    }

    @Test
    public void testBelgianTrustValidator_CertificateThibault() throws Exception {
        final List<X509Certificate> certificateChain = loadCertificateChain(pemCertificateChainThibault);
        validateTrust(certificateChain);

    }

    @Test
    public void testFailingOCSPResponderCertificate() throws Exception {
        final X509Certificate failingOCSPCertificate = loadCertificate(failingOCSPResponderCertificatePEM);
        final X509Certificate citizenCertificate = loadCertificate(citizenCertificatePEM);
        assertThrows(SignatureException.class, () -> failingOCSPCertificate.verify(citizenCertificate.getPublicKey()));
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
