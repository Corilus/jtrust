/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2014-2020 e-Contract.be BV.
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

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private static final Logger LOGGER = LoggerFactory.getLogger(OnlineOcspRepository.class);

    private final static int CONNECTION_TIMEOUT_DURATION = 1000;

    private final static int SOCKET_TIMEOUT_DURATION = 2000;

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
		LOGGER.debug("OCSP URI: {}", ocspUri);
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

		final RequestConfig.Builder requestConfigBuilder = RequestConfig.custom().setConnectTimeout(CONNECTION_TIMEOUT_DURATION)
				.setConnectionRequestTimeout(CONNECTION_TIMEOUT_DURATION).setSocketTimeout(SOCKET_TIMEOUT_DURATION);

		if (null != this.networkConfig) {
			final HttpHost proxy = new HttpHost(this.networkConfig.getProxyHost(), this.networkConfig.getProxyPort());
			requestConfigBuilder.setProxy(proxy);
		}
		final HttpClientContext httpClientContext = HttpClientContext.create();
		if (null != this.credentials) {
			this.credentials.init(httpClientContext);
		}
		final RequestConfig requestConfig = requestConfigBuilder.build();
		final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
		httpClientBuilder.setDefaultRequestConfig(requestConfig);
		final HttpClient httpClient = httpClientBuilder.build();

		HttpResponse httpResponse;
		int responseCode;
		try {
			httpResponse = httpClient.execute(httpPost, httpClientContext);
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
			LOGGER.error("no Content-Type response header");
			return null;
		}
		final String resultContentType = responseContentTypeHeader.getValue();
		if (!"application/ocsp-response".equals(resultContentType)) {
			LOGGER.error("result content type not application/ocsp-response");
			LOGGER.error("actual content-type: {}", resultContentType);
			if ("text/html".equals(resultContentType)) {
				LOGGER.error("content: {}", EntityUtils.toString(httpResponse.getEntity()));
			}
			return null;
		}

		final Header responseContentLengthHeader = httpResponse.getFirstHeader("Content-Length");
		if (null != responseContentLengthHeader) {
			final String resultContentLength = responseContentLengthHeader.getValue();
			if ("0".equals(resultContentLength)) {
				LOGGER.debug("no content returned");
				return null;
			}
		}

		final HttpEntity httpEntity = httpResponse.getEntity();
		final OCSPResp ocspResp = new OCSPResp(httpEntity.getContent());
		LOGGER.debug("OCSP response size: {} bytes", ocspResp.getEncoded().length);
		httpPost.releaseConnection();

		final int ocspRespStatus = ocspResp.getStatus();
		if (OCSPResponseStatus.SUCCESSFUL != ocspRespStatus) {
			LOGGER.debug("OCSP response status: {}", ocspRespStatus);
			return ocspResp;
		}

		final Object responseObject = ocspResp.getResponseObject();
		final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) responseObject;
		final Extension nonceExtension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
		if (null == nonceExtension) {
			LOGGER.debug("no nonce extension in response");
			return ocspResp;
		}

		final ASN1OctetString nonceExtensionValue = extension.getExtnValue();
		final ASN1Primitive nonceValue = ASN1Primitive.fromByteArray(nonceExtensionValue.getOctets());
		final byte[] responseNonce = ((DEROctetString) nonceValue).getOctets();
		if (!Arrays.areEqual(nonce, responseNonce)) {
			LOGGER.error("nonce mismatch");
			return null;
		}
		LOGGER.debug("nonce match");

		return ocspResp;
	}
}
