/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
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

package be.fedict.trust.ocsp;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Arrays;

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.ServerNotAvailableException;
import be.fedict.trust.ServerType;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder
 * to retrieve the OCSP response.
 * 
 * @author Frank Cornelis
 * 
 */
public class OnlineOcspRepository implements OcspRepository {

	private static final Log LOG = LogFactory.getLog(OnlineOcspRepository.class);

	private final NetworkConfig networkConfig;

	private Credentials credentials;

	/**
	 * Main construtor.
	 * 
	 * @param networkConfig
	 *            the optional network configuration used during OCSP Responder
	 *            communication.
	 */
	public OnlineOcspRepository(final NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	/**
	 * Default constructor.
	 */
	public OnlineOcspRepository() {
		this(null);
	}

	/**
	 * Sets the credentials to use to access protected OCSP services.
	 * 
	 * @param credentials
	 */
	public void setCredentials(final Credentials credentials) {
		this.credentials = credentials;
	}

	@Override
	public OCSPResp findOcspResponse(final URI ocspUri, final X509Certificate certificate,
			final X509Certificate issuerCertificate, final Date validationDate) throws ServerNotAvailableException {
		if (null == ocspUri) {
			return null;
		}
		OCSPResp ocspResp = null;
		try {
			ocspResp = getOcspResponse(ocspUri, certificate, issuerCertificate);
		} catch (OperatorCreationException | CertificateEncodingException | OCSPException | IOException e) {
			throw new RuntimeException(e);
		}
		return ocspResp;
	}

	private OCSPResp getOcspResponse(final URI ocspUri, final X509Certificate certificate,
			final X509Certificate issuerCertificate) throws OperatorCreationException,
			CertificateEncodingException, OCSPException, IOException, ServerNotAvailableException {
		LOG.debug("OCSP URI: " + ocspUri);
		final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
		final DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
		final CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
				new JcaX509CertificateHolder(issuerCertificate), certificate.getSerialNumber());
		ocspReqBuilder.addRequest(certId);

		final byte[] nonce = new byte[20];
		final SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(nonce);
		final DEROctetString encodedNonceValue = new DEROctetString(new DEROctetString(nonce).getEncoded());
		final Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, encodedNonceValue);
		final Extensions extensions = new Extensions(extension);
		ocspReqBuilder.setRequestExtensions(extensions);

		final OCSPReq ocspReq = ocspReqBuilder.build();
		final byte[] ocspReqData = ocspReq.getEncoded();

		final HttpPost httpPost = new HttpPost(ocspUri.toString());
		final ContentType contentType = ContentType.create("application/ocsp-request");
		final HttpEntity requestEntity = new ByteArrayEntity(ocspReqData, contentType);
		httpPost.addHeader("User-Agent", "jTrust OCSP Client");
		httpPost.setEntity(requestEntity);

		final DefaultHttpClient httpClient = new DefaultHttpClient();
		if (null != this.networkConfig) {
            final HttpHost proxy = new HttpHost(this.networkConfig.getProxyHost(), this.networkConfig.getProxyPort());
            httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
			int timeout = 5; // seconds
			httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY, proxy);
			httpClient.getParams().setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, timeout * 1000);
			httpClient.getParams().setParameter(CoreConnectionPNames.SO_TIMEOUT, timeout * 1000);
		}
		if (null != this.credentials) {
			this.credentials.init(httpClient.getCredentialsProvider());
		}

		HttpResponse httpResponse;
		int responseCode;
		try {
			httpResponse = httpClient.execute(httpPost);
			final StatusLine statusLine = httpResponse.getStatusLine();
			responseCode = statusLine.getStatusCode();
		} catch (final IOException e) {
			throw new ServerNotAvailableException("OCSP responder is down", ServerType.OCSP, e);
		}

		if (HttpURLConnection.HTTP_OK != responseCode) {
			throw new ServerNotAvailableException("OCSP server responded with status code " + responseCode, ServerType.OCSP);
		}

		final Header responseContentTypeHeader = httpResponse.getFirstHeader("Content-Type");
		if (null == responseContentTypeHeader) {
			LOG.error("no Content-Type response header");
			return null;
		}
		final String resultContentType = responseContentTypeHeader.getValue();
		if (!"application/ocsp-response".equals(resultContentType)) {
			LOG.error("result content type not application/ocsp-response");
			LOG.error("actual content-type: " + resultContentType);
			if ("text/html".equals(resultContentType)) {
				LOG.error("content: " + EntityUtils.toString(httpResponse.getEntity()));
			}
			return null;
		}

		final Header responseContentLengthHeader = httpResponse.getFirstHeader("Content-Length");
		if (null != responseContentLengthHeader) {
			final String resultContentLength = responseContentLengthHeader.getValue();
			if ("0".equals(resultContentLength)) {
				LOG.debug("no content returned");
				return null;
			}
		}

		final HttpEntity httpEntity = httpResponse.getEntity();
		final OCSPResp ocspResp = new OCSPResp(httpEntity.getContent());
		LOG.debug("OCSP response size: " + ocspResp.getEncoded().length + " bytes");
		httpPost.releaseConnection();

		final int ocspRespStatus = ocspResp.getStatus();
		if (OCSPResponseStatus.SUCCESSFUL != ocspRespStatus) {
			LOG.debug("OCSP response status: " + ocspRespStatus);
			return ocspResp;
		}

		final Object responseObject = ocspResp.getResponseObject();
		final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;
		final Extension nonceExtension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		if (null == nonceExtension) {
			LOG.debug("no nonce extension is response");
			return ocspResp;
		}

		final ASN1OctetString nonceExtensionValue = extension.getExtnValue();
		final ASN1Primitive nonceValue = ASN1Primitive.fromByteArray(nonceExtensionValue.getOctets());
		final byte[] responseNonce = ((DEROctetString) nonceValue).getOctets();
		if (!Arrays.areEqual(nonce, responseNonce)) {
			LOG.error("nonce mismatch");
			return null;
		}
		LOG.debug("nonce match");

		return ocspResp;
	}
}
