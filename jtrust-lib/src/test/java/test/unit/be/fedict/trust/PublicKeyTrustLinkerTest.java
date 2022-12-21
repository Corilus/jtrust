/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2018-2022 e-Contract.be BV.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */
package test.unit.be.fedict.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import be.fedict.trust.linker.PublicKeyTrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.revocation.RevocationData;
import be.fedict.trust.test.PKITestUtils;

public class PublicKeyTrustLinkerTest {

	@BeforeAll
	public static void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testHasTrustLink() throws Exception {
		// setup
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testExpiredCertificate() throws Exception {
		// setup
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = Date.from(notAfter.plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL, result.getReason());

	}

	@Test
	public void testCertificateNotYetValid() throws Exception {
		// setup
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = Date.from(notBefore.minusDays(1).atZone(ZoneId.systemDefault()).toInstant());

		// operate
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL, result.getReason());
	}

	@Test
	public void testNoCaFlagFailsNotOnRootCAs() throws Exception {
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter, false);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());
		assertNotNull(result);
		// we only allow this on self-signed roots
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testNoCaFlagFails() throws Exception {
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter, false);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate(), false);

		KeyPair keyPair2 = PKITestUtils.generateKeyPair();
		X509Certificate certificate2 = PKITestUtils.generateCertificate(keyPair2.getPublic(), "CN=Test 2", notBefore,
				notAfter, certificate, keyPair.getPrivate(), false);

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate2, certificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testChildNotAllowToBeCA() throws Exception {
		// setup
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter, true, 0);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate(), true);

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate & verify
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testNoChildFails() throws Exception {
		// setup
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter);

		KeyPair root2keyPair = PKITestUtils.generateKeyPair();
		X509Certificate root2Certificate = PKITestUtils.generateSelfSignedCertificate(root2keyPair, "CN=TestRoot2",
				notBefore, notAfter);

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate & verify
		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(root2Certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testCACertificateNoSKID() throws Exception {
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateCertificate(rootKeyPair.getPublic(), "CN=TestRoot",
				notBefore, notAfter, null, rootKeyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false,
				false, true);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}

	@Test
	public void testChildCACertificateNoAKIDNotSelfSigned() throws Exception {
		// setup
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false,
				true, false);

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		// operate
		TrustLinkerResult result = publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate,
				new RevocationData(), new DefaultAlgorithmPolicy());

		// verify
		assertEquals(TrustLinkerResult.UNDECIDED, result);
	}

	@Test
	public void testAKIDMisMatchSKID() throws Exception {
		KeyPair rootKeyPair = PKITestUtils.generateKeyPair();
		LocalDateTime notBefore = LocalDateTime.now();
		LocalDateTime notAfter = notBefore.plusMonths(1);
		X509Certificate rootCertificate = PKITestUtils.generateSelfSignedCertificate(rootKeyPair, "CN=TestRoot",
				notBefore, notAfter);

		KeyPair keyPair = PKITestUtils.generateKeyPair();
		KeyPair akidKeyPair = PKITestUtils.generateKeyPair();
		X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, rootCertificate, rootKeyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false,
				true, true, akidKeyPair.getPublic());

		PublicKeyTrustLinker publicKeyTrustLinker = new PublicKeyTrustLinker();

		Date validationDate = new Date();

		TrustLinkerResultException result = Assertions.assertThrows(TrustLinkerResultException.class, () -> {
			publicKeyTrustLinker.hasTrustLink(certificate, rootCertificate, validationDate, new RevocationData(),
					new DefaultAlgorithmPolicy());
		});
		assertEquals(TrustLinkerResultReason.NO_TRUST, result.getReason());
	}
}
