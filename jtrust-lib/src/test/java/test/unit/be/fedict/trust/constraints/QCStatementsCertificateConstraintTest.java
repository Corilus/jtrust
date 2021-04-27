/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2017-2021 e-Contract.be BV.
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

package test.unit.be.fedict.trust.constraints;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.constraints.QCStatementsCertificateConstraint;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.test.PKITestUtils;

public class QCStatementsCertificateConstraintTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(QCStatementsCertificateConstraintTest.class);

	@Test
	public void testNoQCStatements() throws Exception {

		// setup
		final QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(Boolean.TRUE);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final LocalDateTime notBefore = LocalDateTime.now();
		final LocalDateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate certificate = PKITestUtils.generateSelfSignedCertificate(keyPair, "CN=Test", notBefore,
				notAfter);

		// operate
		try {
			testedInstance.check(certificate);
			fail();
		} catch (final TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, e.getReason());
		}
	}

	@Test
	public void testQCComplianceMatch() throws Exception {

		// setup
		final QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(Boolean.TRUE);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final LocalDateTime notBefore = LocalDateTime.now();
		final LocalDateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false, false, false,
				null, null, Boolean.TRUE);

		// operate
		testedInstance.check(certificate);
	}

	@Test
	public void testQCComplianceMisMatch() throws Exception {

		// setup
		final QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(Boolean.TRUE);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final LocalDateTime notBefore = LocalDateTime.now();
		final LocalDateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false, false, false,
				null, null, Boolean.FALSE);

		// operate
		try {
			testedInstance.check(certificate);
			fail();
		} catch (final TrustLinkerResultException e) {
			assertEquals(TrustLinkerResultReason.CONSTRAINT_VIOLATION, e.getReason());
		}
	}

	@Test
	public void testNoQCComplianceNeeded() throws Exception {

		// setup
		final QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(null);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final LocalDateTime notBefore = LocalDateTime.now();
		final LocalDateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false, false, false,
				null, null, Boolean.TRUE);

		// operate
		testedInstance.check(certificate);
	}

	@Test
	public void testQCComplianceQcSSCDMatch() throws Exception {

		// setup
		final QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(Boolean.TRUE,
				Boolean.TRUE);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		final LocalDateTime notBefore = LocalDateTime.now();
		final LocalDateTime notAfter = notBefore.plusMonths(1);
		final X509Certificate certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore,
				notAfter, null, keyPair.getPrivate(), true, -1, null, null, null, "SHA1withRSA", false, false, false,
				null, null, Boolean.TRUE, false, true);

		// operate
		testedInstance.check(certificate);
	}

	@Test
	public void testQcSSCD() throws Exception {
		final InputStream certInputStream = QCStatementsCertificateConstraintTest.class
				.getResourceAsStream("/qcstatements.der");
		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certInputStream);
		LOGGER.debug("certificate: {}", certificate);

		final QCStatementsCertificateConstraint testedInstance = new QCStatementsCertificateConstraint(true, true);

		testedInstance.check(certificate);
	}
}
