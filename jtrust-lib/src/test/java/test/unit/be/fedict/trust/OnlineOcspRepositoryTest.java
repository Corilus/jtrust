/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2021 e-Contract.be BV.
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

import static be.fedict.trust.test.World.getFreePort;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import be.fedict.trust.ServerNotAvailableException;
import be.fedict.trust.ocsp.OnlineOcspRepository;
import be.fedict.trust.test.PKITestUtils;

public class OnlineOcspRepositoryTest {

	private Server server;

	private URI ocspUri;

	private OnlineOcspRepository testedInstance;

	private X509Certificate rootCertificate;

	private X509Certificate certificate;

	private KeyPair rootKeyPair;

	@BeforeEach
	public void setUp() throws Exception {
		final int freePort = getFreePort();
		this.server = new Server(freePort);
		final ServletContextHandler servletContextHandler = new ServletContextHandler();
		servletContextHandler.setContextPath("/pki");
		this.server.setHandler(servletContextHandler);
		final String pathSpec = "/test.ocsp";
		servletContextHandler.addServlet(OcspResponderTestServlet.class, pathSpec);
		this.server.start();

		final String servletUrl = "http://localhost:" + freePort + "/pki";
		this.ocspUri = new URI(servletUrl + pathSpec);

		this.testedInstance = new OnlineOcspRepository();

		OcspResponderTestServlet.reset();

		this.rootKeyPair = PKITestUtils.generateKeyPair();
		final LocalDateTime notBefore = LocalDateTime.now();
		final LocalDateTime notAfter = notBefore.plusMonths(1);
		this.rootCertificate = PKITestUtils.generateSelfSignedCertificate(this.rootKeyPair, "CN=TestRoot", notBefore,
				notAfter);

		final KeyPair keyPair = PKITestUtils.generateKeyPair();
		this.certificate = PKITestUtils.generateCertificate(keyPair.getPublic(), "CN=Test", notBefore, notAfter,
				this.rootCertificate, this.rootKeyPair.getPrivate());

		// required for org.bouncycastle.ocsp.CertificateID
		Security.addProvider(new BouncyCastleProvider());
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.server.stop();
	}

	@Test
	public void testInvalidStatusCode() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_NOT_FOUND);

		// operate
		assertThrows(ServerNotAvailableException.class, () -> {
			final OCSPResp result = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate, new Date());

			fail("Expected ServerNotAvailableException, but got: " + result);
		});
	}

	@Test
	public void testOcspServerNotResponding() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

		// operate
		assertThrows(ServerNotAvailableException.class, () -> {
			final OCSPResp result = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate, new Date());

			fail("Expected ServerNotAvailableException, but got: " + result);
		});
	}

	@Test
	public void testMissingResponseContentTypeHeader() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);

		// operate
		final OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testInvalidContentType() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("foobar");

		// operate
		final OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testNoResponseReturned() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");

		// operate
		final OCSPResp ocspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate,
				new Date());

		// verify
		assertNull(ocspResp);
	}

	@Test
	public void testInvalidOcspResponse() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");
		OcspResponderTestServlet.setOcspData("foobar".getBytes());

		// operate & verify
		try {
			this.testedInstance.findOcspResponse(this.ocspUri, this.certificate, this.rootCertificate, new Date());
			fail();
		} catch (final Exception e) {
			// expected
		}
	}

	@Test
	public void testOcspResponse() throws Exception {
		// setup
		OcspResponderTestServlet.setResponseStatus(HttpServletResponse.SC_OK);
		OcspResponderTestServlet.setContentType("application/ocsp-response");

		final OCSPResp ocspResp = PKITestUtils.createOcspResp(this.certificate, false, this.rootCertificate,
				this.rootCertificate, this.rootKeyPair.getPrivate());

		OcspResponderTestServlet.setOcspData(ocspResp.getEncoded());

		// operate
		final OCSPResp resultOcspResp = this.testedInstance.findOcspResponse(this.ocspUri, this.certificate,
				this.rootCertificate, new Date());

		// verify
		assertNotNull(resultOcspResp);
	}

	public static class OcspResponderTestServlet extends HttpServlet {

		private static final Log LOG = LogFactory.getLog(OcspResponderTestServlet.class);

		private static final long serialVersionUID = 1L;

		private static int responseStatus;

		private static String contentType;

		private static byte[] ocspData;

		public static void setResponseStatus(final int responseStatus) {
			OcspResponderTestServlet.responseStatus = responseStatus;
		}

		public static void setContentType(final String contentType) {
			OcspResponderTestServlet.contentType = contentType;
		}

		public static void setOcspData(final byte[] ocspData) {
			OcspResponderTestServlet.ocspData = ocspData;
		}

		public static void reset() {
			OcspResponderTestServlet.responseStatus = 0;
			OcspResponderTestServlet.contentType = null;
			OcspResponderTestServlet.ocspData = null;
		}

		@Override
		protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
				throws ServletException, IOException {
			LOG.debug("doPost");
			if (null != OcspResponderTestServlet.contentType) {
				response.addHeader("Content-Type", OcspResponderTestServlet.contentType);
			}
			if (null != OcspResponderTestServlet.ocspData) {
				final OutputStream outputStream = response.getOutputStream();
				IOUtils.write(OcspResponderTestServlet.ocspData, outputStream);
			}
			if (0 != OcspResponderTestServlet.responseStatus) {
				response.setStatus(OcspResponderTestServlet.responseStatus);
			}
		}
	}
}
