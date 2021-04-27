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

package be.fedict.trust.crl;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.impl.client.HttpClientBuilder;
import org.bouncycastle.x509.NoSuchParserException;
import org.bouncycastle.x509.util.StreamParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.Credentials;
import be.fedict.trust.NetworkConfig;
import be.fedict.trust.ServerNotAvailableException;
import be.fedict.trust.ServerType;

/**
 * Online CRL repository. This CRL repository implementation will download the
 * CRLs from the given CRL URIs.
 * 
 * @author Frank Cornelis
 */
public class OnlineCrlRepository implements CrlRepository {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnlineCrlRepository.class);

	private final static int CONNECTION_TIMEOUT_DURATION = 1000;

	private final static int SOCKET_TIMEOUT_DURATION = 2000;

	private final NetworkConfig networkConfig;

	private Credentials credentials;

	/**
	 * Main construtor.
	 * 
	 * @param networkConfig the optional network configuration used for downloading
	 *                      CRLs.
	 */
	public OnlineCrlRepository(final NetworkConfig networkConfig) {
		this.networkConfig = networkConfig;
	}

	/**
	 * Default constructor.
	 */
	public OnlineCrlRepository() {
		this(null);
	}

	/**
	 * Sets the credentials to use to access protected CRL services.
	 * 
	 * @param credentials
	 */
	public void setCredentials(final Credentials credentials) {
		this.credentials = credentials;
	}

	@Override
	public X509CRL findCrl(final URI crlUri, final X509Certificate issuerCertificate, final Date validationDate) throws ServerNotAvailableException {
		try {
			return getCrl(crlUri);
		} catch (final CRLException e) {
			LOGGER.debug("error parsing CRL: {}", e.getMessage(), e);
			return null;
		} catch (final Exception e) {
			LOGGER.error("find CRL error: {}", e.getMessage(), e);
			return null;
		}
	}

	private X509CRL getCrl(final URI crlUri) throws IOException, CertificateException, CRLException, NoSuchProviderException,
			NoSuchParserException, StreamParsingException, ServerNotAvailableException {
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

		final String downloadUrl = crlUri.toURL().toString();
		LOGGER.debug("downloading CRL from: {}", downloadUrl);
		final HttpGet httpGet = new HttpGet(downloadUrl);
		httpGet.addHeader("User-Agent", "jTrust CRL Client");

		final HttpResponse httpResponse;
		final int statusCode;
		try {
			httpResponse = httpClient.execute(httpGet);
			final StatusLine statusLine = httpResponse.getStatusLine();
			statusCode = statusLine.getStatusCode();
		} catch (final IOException e) {
			throw new ServerNotAvailableException("CRL server is down", ServerType.CRL, e);
		}

		if (HttpURLConnection.HTTP_OK != statusCode) {
			throw new ServerNotAvailableException("CRL server responded with status code " + statusCode, ServerType.CRL);
		}

		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
		LOGGER.debug("certificate factory provider: {}", certificateFactory.getProvider().getName());
		LOGGER.debug("certificate factory class: {}", certificateFactory.getClass().getName());
		final HttpEntity httpEntity = httpResponse.getEntity();
		try (final InputStream content = httpEntity.getContent()) {
			final X509CRL crl = (X509CRL) certificateFactory.generateCRL(content);
			if (crl != null) {
				LOGGER.debug("X509CRL class: {}", crl.getClass().getName());
				LOGGER.debug("CRL size: {} bytes", crl.getEncoded().length);
			} else {
				LOGGER.error("null CRL");
			}
			return crl;
		} finally {
			httpGet.releaseConnection();
		}
	}
}
