package org.springframework.ws.soap.security.wss4j2;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.soap.security.wss4j2.support.CryptoFactoryBean;
import org.w3c.dom.Document;

public class Wss4jMessageInterceptorSamlTestCase extends Wss4jTestCase {

	protected Wss4jSecurityInterceptor interceptor;

	@Override
	protected void onSetup() throws Exception {
		interceptor = new Wss4jSecurityInterceptor();
		interceptor.setSecurementActions("SAMLTokenSigned");
		interceptor.setValidationActions("Signature SAMLTokenSigned");
		CryptoFactoryBean cryptoFactoryBean = new CryptoFactoryBean();
		cryptoFactoryBean.setCryptoProvider(Merlin.class);
		cryptoFactoryBean.setKeyStoreType("jceks");
		cryptoFactoryBean.setKeyStorePassword("123456");
		cryptoFactoryBean.setKeyStoreLocation(new ClassPathResource("private.jks"));
		cryptoFactoryBean.afterPropertiesSet();
		Crypto crypto = cryptoFactoryBean.getObject();
		
		interceptor.setSecurementSamlCallbackHandler(new CallbackHandler() {

			@Override
			public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		        for (int i = 0; i < callbacks.length; i++) {
		            if (callbacks[i] instanceof SAMLCallback) {
		                SAMLCallback callback = (SAMLCallback) callbacks[i];
		                callback.setSamlVersion(Version.SAML_20);
		                callback.setIssuer("Test Issuer");
		                callback.setIssuerCrypto(crypto);
		                callback.setIssuerKeyName("rsaKey");
		                callback.setIssuerKeyPassword("123456");
		                callback.setSignAssertion(true);
		                SubjectBean subjectBean = new SubjectBean(
		                		"Test Subject", "", SAML2Constants.CONF_HOLDER_KEY
		                );
		                KeyInfoBean keyInfo = new KeyInfoBean();
		                CryptoType alias = new CryptoType();
		                alias.setAlias("rsaKey");
		                alias.setType(CryptoType.TYPE.ALIAS);
		                try {
							keyInfo.setCertificate(crypto.getX509Certificates(alias)[0]);
						} catch (WSSecurityException e) {
						}
		                subjectBean.setKeyInfo(keyInfo);
		                callback.setSubject(subjectBean);
		            } else {
		                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
		            }
		        }
			}
		});
		interceptor.setSecurementSignatureCrypto(crypto);
		interceptor.setValidationSignatureCrypto(crypto);
		interceptor.afterPropertiesSet();
	}

	@Test
	public void testAddSaml() throws Exception {

		interceptor.setSecurementPassword("123456");
		interceptor.setSecurementUsername("rsaKey");
		SoapMessage message = loadSoap11Message("empty-soap.xml");
		MessageContext messageContext = getSoap11MessageContext(message);

		interceptor.secureMessage(message, messageContext);
		Document document = getDocument(message);

		assertXpathExists("Absent SAML element",
				"/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml2:Assertion", document);

		// lets verify the signature that we've just generated
		interceptor.validateMessage(message, messageContext);
	}
}
