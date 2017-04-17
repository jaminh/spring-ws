package org.springframework.ws.soap.security.wss4j2;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.security.cert.X509Certificate;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.soap.security.wss4j2.support.CryptoFactoryBean;
import org.w3c.dom.Document;

public abstract class Wss4jMessageInterceptorSamlTestCase extends Wss4jTestCase {

	protected Wss4jSecurityInterceptor interceptor;

	@Override
	protected void onSetup() throws Exception {
		interceptor = new Wss4jSecurityInterceptor();
		interceptor.setSecurementActions("SAMLTokenSigned");
		interceptor.setValidationActions("SAMLTokenSigned Signature");
		CryptoFactoryBean cryptoFactoryBean = new CryptoFactoryBean();
		cryptoFactoryBean.setCryptoProvider(Merlin.class);
		cryptoFactoryBean.setKeyStoreType("jceks");
		cryptoFactoryBean.setKeyStorePassword("123456");
		cryptoFactoryBean.setKeyStoreLocation(new ClassPathResource("private.jks"));
		cryptoFactoryBean.afterPropertiesSet();

		Crypto crypto = cryptoFactoryBean.getObject();
		CryptoType alias = new CryptoType(CryptoType.TYPE.ALIAS);
		alias.setAlias("rsakey");
		X509Certificate[] certs = crypto.getX509Certificates(alias);
		if (certs == null || certs.length < 1) {
			throw new IllegalStateException("Could not get certificate for SAML signature confirmation data");
		}
		interceptor.setSecurementSignatureCrypto(crypto);
		interceptor.setValidationSignatureCrypto(crypto);
		interceptor.setSecurementSamlCallbackHandler(getSamlCalbackHandler(crypto, certs[0]));
		interceptor.afterPropertiesSet();

	}

	@Test
	public void testAddSAML() throws Exception {
		interceptor.setSecurementPassword("123456");
		interceptor.setSecurementUsername("rsakey");
		SoapMessage message = loadSoap11Message("empty-soap.xml");
		MessageContext messageContext = getSoap11MessageContext(message);

		interceptor.secureMessage(message, messageContext);
		Document document = getDocument(message);

		assertXpathExists("Absent SAML Assertion element",
				"/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml2:Assertion", document);

		// lets verify the SAML assertion that we've just generated
		interceptor.validateMessage(message, messageContext);
	}

	protected CallbackHandler getSamlCalbackHandler(Crypto crypto, X509Certificate subjectCertificate) {
		return new SamlCallbackHandler(crypto, subjectCertificate);
	}

	private class SamlCallbackHandler implements CallbackHandler {

		private X509Certificate subjectCertificate;

		private Crypto crypto;

		public SamlCallbackHandler(Crypto crypto, X509Certificate subjectCertificate) {
			this.crypto = crypto;
			this.subjectCertificate = subjectCertificate;
		}

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

			for (int i = 0; i < callbacks.length; i++) {
				if (callbacks[i] instanceof SAMLCallback) {
					SAMLCallback callback = (SAMLCallback) callbacks[i];
					callback.setIssuerCrypto(crypto);
					callback.setIssuerKeyName("rsakey");
					callback.setIssuerKeyPassword("123456");
					callback.setSignAssertion(true);
					SubjectBean subject = new SubjectBean();
					subject.setSubjectName("Test Subject");
					subject.setSubjectConfirmationMethod(SAML2Constants.CONF_HOLDER_KEY);
					KeyInfoBean keyInfo = new KeyInfoBean();
					keyInfo.setCertificate(subjectCertificate);
					subject.setKeyInfo(keyInfo);
					callback.setSubject(subject);
				}
			}
		}

	}

}
