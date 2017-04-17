package org.springframework.ws.soap.security.wss4j2;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.saml.SAMLCallback;
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
		interceptor.setValidationActions("SAMLTokenSigned");
		CryptoFactoryBean cryptoFactoryBean = new CryptoFactoryBean();
		cryptoFactoryBean.setCryptoProvider(Merlin.class);
		cryptoFactoryBean.setKeyStoreType("jceks");
		cryptoFactoryBean.setKeyStorePassword("123456");
		cryptoFactoryBean.setKeyStoreLocation(new ClassPathResource("private.jks"));

		cryptoFactoryBean.afterPropertiesSet();
		interceptor.setSecurementSignatureCrypto(cryptoFactoryBean
				.getObject());
		interceptor.setValidationSignatureCrypto(cryptoFactoryBean
				.getObject());
		interceptor.setSecurementSamlCallbackHandler(getSamlCalbackHandler(cryptoFactoryBean
				.getObject()));
		interceptor.afterPropertiesSet();

	}
	
	@Test
	public void testAddSAML() throws Exception
	{
		//interceptor.setSecurementPassword("123456");
		//interceptor.setSecurementUsername("rsaKey");
		//SoapMessage message = loadSoap11Message("empty-soap.xml");
		//MessageContext messageContext = getSoap11MessageContext(message);

		//interceptor.secureMessage(message, messageContext);
		//Document document = getDocument(message);

		//assertXpathExists("Absent SAML Assertion element",
		//		"/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/saml:Assertion", document);

		//// lets verify the signature that we've just generated
		//interceptor.validateMessage(message, messageContext);
	}
	
	protected CallbackHandler getSamlCalbackHandler(Crypto crypto)
	{
		return new SamlCallbackHandler(crypto);
	}
	
	private class SamlCallbackHandler implements CallbackHandler {
		
		private Crypto crypto;
		
		public SamlCallbackHandler(Crypto crypto)
		{
			this.crypto = crypto;
		}
	
		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

	        for (int i = 0; i < callbacks.length; i++) {
	            if (callbacks[i] instanceof SAMLCallback) {
	            	SAMLCallback callback = (SAMLCallback) callbacks[i];
	            	callback.setIssuerCrypto(crypto);
	            }
	        }
		}
		
	}

}
