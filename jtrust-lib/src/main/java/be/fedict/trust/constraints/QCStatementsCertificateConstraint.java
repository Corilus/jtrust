/*
 * Java Trust Project.
 * Copyright (C) 2009-2010 FedICT.
 * Copyright (C) 2014-2018 e-Contract.be BVBA.
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

package be.fedict.trust.constraints;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;

/**
 * QCStatements certificate constraint.
 * 
 * @author Frank Cornelis
 * 
 * @see <a href="http://www.ietf.org/rfc/rfc3039.txt">RFC 3039</a>
 * @see <a href=
 *      "http://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf">
 *      ETSI EN 319 412-5 V2.1.1</a>
 */
public class QCStatementsCertificateConstraint implements CertificateConstraint {

	private static final Log LOG = LogFactory.getLog(QCStatementsCertificateConstraint.class);

	static final ASN1ObjectIdentifier id_etsi_qcs_QcType = new ASN1ObjectIdentifier("0.4.0.1862.1.6");

	static final ASN1ObjectIdentifier id_etsi_qcs_QcType_eSign = id_etsi_qcs_QcType.branch("1");
	static final ASN1ObjectIdentifier id_etsi_qcs_QcType_eSeal = id_etsi_qcs_QcType.branch("2");

	private final Boolean qcComplianceFilter;

	private final Boolean qcSSCDFilter;

	private final Boolean qcTypeSignFilter;

	private final Boolean qcTypeSealFilter;

	public QCStatementsCertificateConstraint(final Boolean qcComplianceFilter) {
		this(qcComplianceFilter, null);
	}

	public QCStatementsCertificateConstraint(final Boolean qcComplianceFilter, final Boolean qcSSCDFilter) {
		this(qcComplianceFilter, qcSSCDFilter, null, null);
	}

	public QCStatementsCertificateConstraint(final Boolean qcComplianceFilter, final Boolean qcSSCDFilter, final Boolean qcTypeSignFilter,
			final Boolean qcTypeSealFilter) {
		this.qcComplianceFilter = qcComplianceFilter;
		this.qcSSCDFilter = qcSSCDFilter;
		this.qcTypeSignFilter = qcTypeSignFilter;
		this.qcTypeSealFilter = qcTypeSealFilter;
	}

	@Override
	public void check(final X509Certificate certificate) throws TrustLinkerResultException, Exception {
		final byte[] extensionValue = certificate.getExtensionValue(Extension.qCStatements.getId());
		if (null == extensionValue) {
			throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
					"missing QCStatements extension");
		}

		boolean qcCompliance = false;
		boolean qcSSCD = false;
		boolean eSign = false;
		boolean eSeal = false;

		try (final ASN1InputStream extensionStream = new ASN1InputStream(new ByteArrayInputStream(extensionValue))) {
			final DEROctetString octetString = (DEROctetString) extensionStream.readObject();
			try (final ASN1InputStream octetStream = new ASN1InputStream(octetString.getOctets())) {
				final ASN1Sequence qcStatements = (ASN1Sequence) octetStream.readObject();
				final Enumeration<?> qcStatementEnum = qcStatements.getObjects();
				while (qcStatementEnum.hasMoreElements()) {
					final QCStatement qcStatement = QCStatement.getInstance(qcStatementEnum.nextElement());
					final ASN1ObjectIdentifier statementId = qcStatement.getStatementId();
					LOG.debug("statement Id: " + statementId.getId());
					if (QCStatement.id_etsi_qcs_QcCompliance.equals(statementId)) {
						qcCompliance = true;
					}
					if (QCStatement.id_etsi_qcs_QcSSCD.equals(statementId)) {
						qcSSCD = true;
					}
					if (id_etsi_qcs_QcType.equals(statementId)) {
						final ASN1Encodable statementInfo = qcStatement.getStatementInfo();
						final ASN1Sequence qcTypeSequence = ASN1Sequence.getInstance(statementInfo);
						final Enumeration<?> qcType = qcTypeSequence.getObjects();
						while (qcType.hasMoreElements()) {
							final ASN1ObjectIdentifier qcTypeOID = ASN1ObjectIdentifier.getInstance(qcType.nextElement());
							LOG.debug("QcType: " + qcTypeOID);
							if (id_etsi_qcs_QcType_eSign.equals(qcTypeOID)) {
								eSign = true;
							}
							if (id_etsi_qcs_QcType_eSeal.equals(qcTypeOID)) {
								eSeal = true;
							}
						}
					}
				}
			}
		}

		if (null != this.qcComplianceFilter) {
			if (qcCompliance != this.qcComplianceFilter) {
				LOG.error("qcCompliance QCStatements error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QCStatements not matching");
			}
		}

		if (null != this.qcSSCDFilter) {
			if (qcSSCD != this.qcSSCDFilter) {
				LOG.error("qcSSCD QCStatements error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QCStatements not matching");
			}
		}

		if (null != this.qcTypeSignFilter) {
			if (eSign != this.qcTypeSignFilter) {
				LOG.error("QcType eSign error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QcType eSign not matching");
			}
		}

		if (null != this.qcTypeSealFilter) {
			if (eSeal != this.qcTypeSealFilter) {
				LOG.error("QcType eSeal error");
				throw new TrustLinkerResultException(TrustLinkerResultReason.CONSTRAINT_VIOLATION,
						"QcType eSeal not matching");
			}
		}
	}
}
