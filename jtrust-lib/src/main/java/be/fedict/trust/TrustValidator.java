/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014-2021 e-Contract.be BV.
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

package be.fedict.trust;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.constraints.CertificateConstraint;
import be.fedict.trust.linker.CustomCertSignValidator;
import be.fedict.trust.linker.TrustLinker;
import be.fedict.trust.linker.TrustLinkerResult;
import be.fedict.trust.linker.TrustLinkerResultException;
import be.fedict.trust.linker.TrustLinkerResultReason;
import be.fedict.trust.policy.AlgorithmPolicy;
import be.fedict.trust.policy.DefaultAlgorithmPolicy;
import be.fedict.trust.repository.CertificateRepository;
import be.fedict.trust.revocation.RevocationData;

/**
 * Trust Validator.
 * <p>
 * Notice that this component is not thread-safe as it is using internal state.
 * </p>
 * 
 * @author Frank Cornelis
 * 
 */
public class TrustValidator {

	private static final Logger LOGGER = LoggerFactory.getLogger(TrustValidator.class);

	private final CertificateRepository certificateRepository;

	private final List<TrustLinker> trustLinkers;

	private final List<CertificateConstraint> certificateConstraints;

	private RevocationData revocationData;

	private AlgorithmPolicy algorithmPolicy;

	/**
	 * Main constructor.
	 * 
	 * @param certificateRepository the certificate repository used by this trust
	 *                              validator.
	 */
	public TrustValidator(final CertificateRepository certificateRepository) {
		this(certificateRepository, null);
	}

	/**
	 * Main constructor.
	 * 
	 * @param certificateRepository the certificate repository used by this trust
	 *                              validator.
	 * @param revocationData        optional {@link RevocationData} object. If not
	 *                              <code>null</code> the added
	 *                              {@link TrustLinker}'s should fill it up with
	 *                              used revocation data.
	 */
	public TrustValidator(final CertificateRepository certificateRepository, final RevocationData revocationData) {
		this.certificateRepository = certificateRepository;
		this.trustLinkers = new LinkedList<>();
		this.certificateConstraints = new LinkedList<>();
		this.revocationData = revocationData;
		this.algorithmPolicy = new DefaultAlgorithmPolicy();
	}

	/**
	 * Adds a trust linker to this trust validator. The order in which trust linkers
	 * are added determine the runtime behavior of the trust validator.
	 * 
	 * @param trustLinker the trust linker component.
	 */
	public void addTrustLinker(final TrustLinker trustLinker) {
		this.trustLinkers.add(trustLinker);
	}

	/**
	 * Sets the algorithm policy to be used when validation used signature
	 * algorithms.
	 * 
	 * @param algorithmPolicy the algorithm policy component.
	 */
	public void setAlgorithmPolicy(final AlgorithmPolicy algorithmPolicy) {
		this.algorithmPolicy = algorithmPolicy;
	}

	/**
	 * Adds a certificate constraint to this trust validator. Keep this typo-version
	 * of addCertificateContrainT for downwards compatibility.
	 * 
	 * @param certificateConstraint the certificate constraint component.
	 * @deprecated
	 * @see TrustValidator#addCertificateConstraint(CertificateConstraint)
	 */
	@Deprecated
	public void addCertificateConstrain(final CertificateConstraint certificateConstraint) {
		this.certificateConstraints.add(certificateConstraint);
	}

	/**
	 * Adds a certificate constraint to this trust validator.
	 *
	 * @param certificateConstraint the certificate constraint component.
	 */
	public void addCertificateConstraint(final CertificateConstraint certificateConstraint) {
		this.certificateConstraints.add(certificateConstraint);
	}

	/**
	 * Validates whether the given certificate path is valid according to the
	 * configured trust linkers.
	 * 
	 * @param certificatePath the X509 certificate path to validate.
	 * @throws TrustLinkerResultException in case the certificate path is invalid.
	 * @see #isTrusted(List, Date)
	 */
	public void isTrusted(final List<X509Certificate> certificatePath) throws TrustLinkerResultException {
		isTrusted(certificatePath, new Date());
	}

	/**
	 * Validates whether the given certificate path is valid according to the
	 * configured trust linkers.
	 * 
	 * @param certificatePath the X509 certificate path to validate.
	 * @param expiredMode     set to <code>true</code> for validation mode of
	 *                        expired certificates.
	 * @throws TrustLinkerResultException in case the certificate path is invalid.
	 * @see #isTrusted(List, Date)
	 */
	public void isTrusted(final List<X509Certificate> certificatePath, final boolean expiredMode)
			throws TrustLinkerResultException {
		isTrusted(certificatePath, new Date(), expiredMode);
	}

	/**
	 * Validates whether the given certificate path is valid according to the
	 * configured trust linkers. Convenience method when loading a certificate chain
	 * directly from a JCA key store implementation.
	 * 
	 * @param certificates
	 * @throws be.fedict.trust.linker.TrustLinkerResultException
	 */
	public void isTrusted(final Certificate[] certificates) throws TrustLinkerResultException {
		final List<X509Certificate> certificateChain = new LinkedList<>();
		for (final Certificate certificate : certificates) {
			final X509Certificate x509Certificate = (X509Certificate) certificate;
			certificateChain.add(x509Certificate);
		}
		isTrusted(certificateChain);
	}

	/**
	 * Returns the {@link RevocationData} returned by the configured
	 * {@link TrustLinker}'s if a {@link RevocationData} object was specified in the
	 * constructor.
	 * 
	 * @return {@link RevocationData}
	 */
	public RevocationData getRevocationData() {

		return this.revocationData;
	}

	/**
	 * Checks whether the given certificate is self-signed.
	 * 
	 * @param certificate the X509 certificate.
	 */
	public static void isSelfSigned(final X509Certificate certificate) throws TrustLinkerResultException {
		checkSelfSigned(certificate);
	}

	/**
	 * Gives back the trust linker result of a verification of a self-signed X509
	 * certificate.
	 * 
	 * @param certificate the self-signed certificate to validate.
	 */
	public static void checkSelfSigned(final X509Certificate certificate) throws TrustLinkerResultException {
		if (false == certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
			throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST,
					"root certificate should be self-signed: " + certificate.getSubjectX500Principal());
		}
		try {
			CustomCertSignValidator.verify(certificate);
		} catch (final Exception e) {
			throw new TrustLinkerResultException(TrustLinkerResultReason.INVALID_SIGNATURE,
					"certificate signature error: " + e.getMessage());
		}
	}

	private void checkSignatureAlgorithm(final String signatureAlgorithm, final Date validationDate)
			throws TrustLinkerResultException {
		try {
			this.algorithmPolicy.checkSignatureAlgorithm(signatureAlgorithm, validationDate);
		} catch (final TrustLinkerResultException e) {
			// re-wrapping this type of exception doesn't bring anything
			throw e;
		} catch (final Exception e) {
			throw new TrustLinkerResultException(TrustLinkerResultReason.INVALID_ALGORITHM,
					"Invalid signature algorithm: " + signatureAlgorithm);
		}
	}

	/**
	 * Validates whether the certificate path was valid at the given validation
	 * date.
	 * 
	 * @param certificatePath the X509 certificate path to be validated.
	 * @param validationDate  the date at which the certificate path validation
	 *                        should be verified.
	 * @see #isTrusted(List)
	 */
	public void isTrusted(final List<X509Certificate> certificatePath, final Date validationDate)
			throws TrustLinkerResultException {
		isTrusted(certificatePath, validationDate, false);
	}

	/**
	 * Validates whether the certificate path was valid at the given validation
	 * date.
	 * 
	 * @param certificatePath the X509 certificate path to be validated.
	 * @param validationDate  the date at which the certificate path validation
	 *                        should be verified.
	 * @see #isTrusted(List)
	 */
	public void isTrusted(final List<X509Certificate> certificatePath, final Instant validationDate)
			throws TrustLinkerResultException {
		isTrusted(certificatePath, Date.from(validationDate), false);
	}

	/**
	 * Validates whether the certificate path was valid at the given validation
	 * date.
	 * 
	 * @param certificatePath the X509 certificate path to be validated.
	 * @param validationDate  the date at which the certificate path validation
	 *                        should be verified.
	 * @see #isTrusted(List)
	 */
	public void isTrusted(final List<X509Certificate> certificatePath, final LocalDateTime validationDate)
			throws TrustLinkerResultException {
		isTrusted(certificatePath, Date.from(validationDate.atZone(ZoneId.systemDefault()).toInstant()), false);
	}

	/**
	 * Validates whether the certificate path was valid at the given validation
	 * date.
	 * 
	 * @param certificatePath the X509 certificate path to be validated.
	 * @param validationDate  the date at which the certificate path validation
	 *                        should be verified.
	 * @param expiredMode     set to <code>true</code> for validation mode of
	 *                        expired certificates.
	 * @see #isTrusted(List)
	 */
	public void isTrusted(final List<X509Certificate> certificatePath, final Date validationDate, final boolean expiredMode)
			throws TrustLinkerResultException {
		if (certificatePath.isEmpty()) {
			throw new TrustLinkerResultException(TrustLinkerResultReason.UNSPECIFIED, "certificate path is empty");
		}
		for (final X509Certificate certificate : certificatePath) {
			if (null == certificate) {
				throw new TrustLinkerResultException(TrustLinkerResultReason.UNSPECIFIED,
						"certificate path contains null certificate");
			}
		}
		if (expiredMode) {
			LOGGER.debug("expired certificate validation mode");
		}

		int certIdx = certificatePath.size() - 1;
		X509Certificate certificate = certificatePath.get(certIdx);
		LOGGER.debug("verifying root certificate: {}", certificate.getSubjectX500Principal());
		checkSelfSigned(certificate);
		// check certificate signature
		checkSignatureAlgorithm(certificate.getSigAlgName(), validationDate);
		checkSelfSignedTrust(certificate, validationDate, expiredMode);

		certIdx--;

		while (certIdx >= 0) {
			final X509Certificate childCertificate = certificatePath.get(certIdx);
			LOGGER.debug("verifying certificate: {}", childCertificate.getSubjectX500Principal());
			certIdx--;
			checkTrustLink(childCertificate, certificate, validationDate);
			certificate = childCertificate;
		}

		for (final CertificateConstraint certificateConstraint : this.certificateConstraints) {
			final String certificateConstraintName = certificateConstraint.getClass().getSimpleName();
			LOGGER.debug("certificate constraint check: {}", certificateConstraintName);
			try {
				certificateConstraint.check(certificate);
			} catch (final TrustLinkerResultException e) {
				// let this specific type of exception pass as is
				throw e;
			} catch (final Exception e) {
				throw new TrustLinkerResultException(TrustLinkerResultReason.UNSPECIFIED,
						"certificate constraint error " + certificateConstraintName + ": " + e.getMessage(), e);
			}
		}
	}

	private void checkTrustLink(final X509Certificate childCertificate, final X509Certificate certificate, final Date validationDate)
			throws TrustLinkerResultException {
		if (null == childCertificate) {
			return;
		}
		// check certificate signature
		checkSignatureAlgorithm(childCertificate.getSigAlgName(), validationDate);

		boolean sometrustLinkerTrusts = false;
		for (final TrustLinker trustLinker : this.trustLinkers) {
			LOGGER.debug("trying trust linker: {}", trustLinker.getClass().getSimpleName());
			TrustLinkerResult trustLinkerResult;
			try {
				trustLinkerResult = trustLinker.hasTrustLink(childCertificate, certificate, validationDate,
						this.revocationData, this.algorithmPolicy);
			} catch (final TrustLinkerResultException e) {
				// we let this type of exception pass as is
				LOGGER.warn("trust linker exception: " + e.getMessage(), e);
				throw e;
			} catch (final Exception e) {
				LOGGER.warn("trust linker error: " + e.getMessage(), e);
				throw new TrustLinkerResultException(TrustLinkerResultReason.UNSPECIFIED,
						"trust linker error: " + e.getMessage(), e);
			}
			if (null == trustLinkerResult) {
				LOGGER.warn("trust linker result should not be NULL");
			}
			if (TrustLinkerResult.TRUSTED == trustLinkerResult) {
				// we don't break as there still might be a trust linker that
				// complains
				sometrustLinkerTrusts = true;
			}
		}
		if (false == sometrustLinkerTrusts) {
			final String message = "no trust between " + childCertificate.getSubjectX500Principal() + " and "
					+ certificate.getSubjectX500Principal();
			LOGGER.warn(message);
			throw new TrustLinkerResultException(TrustLinkerResultReason.NO_TRUST, message);
		}
	}

	private void checkSelfSignedTrust(final X509Certificate certificate, final Date validationDate, final boolean expiredMode)
			throws TrustLinkerResultException {
		if (certificate.getNotBefore().after(validationDate)) {
			LOGGER.error("certificate not yet valid");
			LOGGER.error("validation date: {}", validationDate);
			LOGGER.error("not before: {}", certificate.getNotBefore());
			LOGGER.error("not after: {}", certificate.getNotAfter());
			throw new TrustLinkerResultException(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
					"certificate not yet valid");
		}
		if (certificate.getNotAfter().before(validationDate)) {
			if (!expiredMode) {
				LOGGER.error("certificate expired");
				LOGGER.error("validation date: {}", validationDate);
				LOGGER.error("not before: {}", certificate.getNotBefore());
				LOGGER.error("not after: {}", certificate.getNotAfter());
				throw new TrustLinkerResultException(TrustLinkerResultReason.INVALID_VALIDITY_INTERVAL,
						"certificate expired");
			} else {
				LOGGER.warn("certificate expired");
				LOGGER.warn("validation date: {}", validationDate);
				LOGGER.warn("not before: {}", certificate.getNotBefore());
				LOGGER.warn("not after: {}", certificate.getNotAfter());
			}
		}
		if (this.certificateRepository.isTrustPoint(certificate)) {
			return;
		}
		LOGGER.warn("self-signed certificate not in repository: {}", certificate.getSubjectX500Principal());
		throw new TrustLinkerResultException(TrustLinkerResultReason.ROOT,
				"self-signed certificate not in repository: " + certificate.getSubjectX500Principal());
	}

	/**
	 * Sets the revocation data container used by this trust validator while
	 * validating certificate chains.
	 * 
	 * @param revocationData
	 */
	public void setRevocationData(final RevocationData revocationData) {
		this.revocationData = revocationData;
	}
}
