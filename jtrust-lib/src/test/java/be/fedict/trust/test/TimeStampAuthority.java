/*
 * Java Trust Project.
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

package be.fedict.trust.test;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.Store;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.ServletTester;

public class TimeStampAuthority implements EndpointProvider {

	private final World world;

	private final CertificationAuthority certificationAuthority;

	private final String identifier;

	private KeyPair keyPair;

	private X509Certificate certificate;

	private List<X509Certificate> certificateChain;

	private String url;

	private final static Map<String, TimeStampAuthority> timeStampAuthorities;

	static {
		timeStampAuthorities = new HashMap<>();
	}

	public TimeStampAuthority(World world, CertificationAuthority certificationAuthority) {
		this.identifier = UUID.randomUUID().toString();
		timeStampAuthorities.put(this.identifier, this);
		this.world = world;
		this.world.addEndpointProvider(this);
		this.certificationAuthority = certificationAuthority;
	}

	@Override
	public void addEndpoints(ServletTester servletTester) throws Exception {
		String pathSpec = "/" + this.identifier + "/tsa";
		ServletHolder servletHolder = servletTester.addServlet(TSAServlet.class, pathSpec);
		servletHolder.setInitParameter("identifier", this.identifier);
	}

	@Override
	public void started(String url) throws Exception {
		this.keyPair = PKITestUtils.generateKeyPair();
		this.certificate = this.certificationAuthority.issueTimeStampAuthority(this.keyPair.getPublic(), "CN=TSA");
		this.url = url + "/" + this.identifier + "/tsa";
		this.certificateChain = new LinkedList<>();
		this.certificateChain.add(this.certificate);
		CertificationAuthority issuer = this.certificationAuthority;
		while (issuer != null) {
			this.certificateChain.add(issuer.getCertificate());
			issuer = issuer.getIssuer();
		}
	}

	public String getUrl() {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		return this.url;
	}

	public static final class TSAServlet extends HttpServlet {
		private static final Log LOG = LogFactory.getLog(TSAServlet.class);

		private static final long serialVersionUID = 1L;

		private String identifier;

		@Override
		protected void doPost(HttpServletRequest request, HttpServletResponse response)
				throws ServletException, IOException {
			try {
				_doPost(request, response);
			} catch (Exception e) {
				LOG.error(e);
			}
		}

		private void _doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
			TimeStampAuthority timeStampAuthority = getTimeStampAuthority();

			byte[] reqData = IOUtils.toByteArray(request.getInputStream());
			TimeStampRequest timeStampRequest = new TimeStampRequest(reqData);

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
					new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA",
							timeStampAuthority.keyPair.getPrivate(), timeStampAuthority.certificate),
					new JcaDigestCalculatorProviderBuilder().build().get(
							new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
					new ASN1ObjectIdentifier("1.2"));

			LOG.debug("certificate chain size: " + timeStampAuthority.certificateChain.size());
			Store certs = new JcaCertStore(timeStampAuthority.certificateChain);
			tsTokenGen.addCertificates(certs);

			TimeStampResponseGenerator timeStampResponseGenerator = new TimeStampResponseGenerator(tsTokenGen,
					TSPAlgorithms.ALLOWED);
			TimeStampResponse timeStampResponse = timeStampResponseGenerator.generate(timeStampRequest, BigInteger.ONE,
					new Date());

			response.setContentType("application/timestamp-reply");
			OutputStream outputStream = response.getOutputStream();
			IOUtils.write(timeStampResponse.getEncoded(), outputStream);
		}

		@Override
		public void init(ServletConfig config) throws ServletException {
			this.identifier = config.getInitParameter("identifier");
		}

		private TimeStampAuthority getTimeStampAuthority() {
			return timeStampAuthorities.get(this.identifier);
		}
	}
}
