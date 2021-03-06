/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2018 e-Contract.be BVBA.
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

package be.fedict.trust.ocsp;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Date;

import be.fedict.trust.ServerNotAvailableException;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Interface for OCSP repository components.
 * 
 * @author Frank Cornelis
 * 
 */
public interface OcspRepository {

	/**
	 * Finds the requested OCSP response in this OCSP repository.
	 * 
	 * @param ocspUri
	 *            the OCSP responder URI. Can be <code>null</code>.
	 * @param certificate
	 *            the X509 certificate.
	 * @param issuerCertificate
	 *            the X509 issuer certificate.
	 * @param validationDate
	 *            the validation date.
	 * @throws ServerNotAvailableException
	 * 			  {@link ServerNotAvailableException} if the OCSP server is not responding.
	 * @return the OCSP response, or <code>null</code> if not found.
	 */
	OCSPResp findOcspResponse(URI ocspUri, X509Certificate certificate,
			X509Certificate issuerCertificate, Date validationDate) throws ServerNotAvailableException;
}
