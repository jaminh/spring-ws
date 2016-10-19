/*
 * Copyright 2005-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.ws.soap.security.wss4j2;

import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.junit.Test;

import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.ws.context.DefaultMessageContext;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapMessage;
import org.springframework.ws.soap.security.WsSecuritySecurementException;
import org.springframework.ws.soap.security.WsSecurityValidationException;

import static org.junit.Assert.*;

public abstract class Wss4jInterceptorTestCase extends Wss4jTestCase {

	@Test
	public void testHandleRequest() throws Exception {
		SoapMessage request = loadSoap11Message("empty-soap.xml");
		final Object requestMessage = getMessage(request);
		SoapMessage validatedRequest = loadSoap11Message("empty-soap.xml");
		final Object validatedRequestMessage = getMessage(validatedRequest);
		Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor() {
			@Override
			protected void secureMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecuritySecurementException {
				fail("secure not expected");
			}

			@Override
			protected void validateMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecurityValidationException {
				assertEquals("Invalid message", requestMessage, getMessage(soapMessage));
				setMessage(soapMessage, validatedRequestMessage);
			}
		};
		MessageContext context = new DefaultMessageContext(request, getSoap11MessageFactory());
		interceptor.handleRequest(context, null);
		assertEquals("Invalid request", validatedRequestMessage, getMessage((SoapMessage) context.getRequest()));
	}

	@Test
	public void testHandleResponse() throws Exception {
		SoapMessage securedResponse = loadSoap11Message("empty-soap.xml");
		final Object securedResponseMessage = getMessage(securedResponse);

		Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor() {

			@Override
			protected void secureMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecuritySecurementException {
				setMessage(soapMessage, securedResponseMessage);
			}

			@Override
			protected void validateMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecurityValidationException {
				fail("validate not expected");
			}

		};
		SoapMessage request = loadSoap11Message("empty-soap.xml");
		MessageContext context = new DefaultMessageContext(request, getSoap11MessageFactory());
		context.getResponse();
		interceptor.handleResponse(context, null);
		assertEquals("Invalid response", securedResponseMessage, getMessage((SoapMessage) context.getResponse()));
	}

	@Test
	public void testHandleRequestNoValidationActions() throws Exception {
		SoapMessage request = loadSoap11Message("empty-soap.xml");
		final Object requestMessage = getMessage(request);
		Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor() {
			@Override
			protected void secureMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecuritySecurementException {
				fail("secure not expected");
			}
		};
		MessageContext context = new DefaultMessageContext(request, getSoap11MessageFactory());
		interceptor.handleRequest(context, null);
		assertEquals("Invalid request", requestMessage, getMessage((SoapMessage) context.getRequest()));
	}

	@Test
	public void testHandleRequestNoSecurity() throws Exception {
		SoapMessage request = loadSoap11Message("empty-soap.xml");
		final Object requestMessage = getMessage(request);
		Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor() {
			@Override
			protected void secureMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecuritySecurementException {
				fail("secure not expected");
			}
		};
		MessageContext context = new DefaultMessageContext(request, getSoap11MessageFactory());
		interceptor.setValidationActions("NoSecurity");
		interceptor.handleRequest(context, null);
		assertEquals("Invalid request", requestMessage, getMessage((SoapMessage) context.getRequest()));
	}
	


	@Test
	public void testHandleResponseNoSecurementActions() throws Exception {
		SoapMessage securedResponse = loadSoap11Message("empty-soap.xml");
		final Object securedResponseMessage = getMessage(securedResponse);

		Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor() {

			@Override
			protected void validateMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecurityValidationException {
				fail("validate not expected");
			}

		};
		SoapMessage request = loadSoap11Message("empty-soap.xml");
		MessageContext context = new DefaultMessageContext(request, getSoap11MessageFactory());
		context.setResponse(securedResponse);
		interceptor.handleResponse(context, null);
		assertEquals("Invalid response", securedResponseMessage, getMessage((SoapMessage) context.getResponse()));
	}

	@Test
	public void testHandleResponseNoSecurity() throws Exception {
		SoapMessage securedResponse = loadSoap11Message("empty-soap.xml");
		final Object securedResponseMessage = getMessage(securedResponse);

		Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor() {

			@Override
			protected void validateMessage(SoapMessage soapMessage, MessageContext messageContext)
					throws WsSecurityValidationException {
				fail("validate not expected");
			}

		};
		SoapMessage request = loadSoap11Message("empty-soap.xml");
		MessageContext context = new DefaultMessageContext(request, getSoap11MessageFactory());
		context.setResponse(securedResponse);
		interceptor.setSecurementActions("NoSecurity");
		interceptor.handleResponse(context, null);
		assertEquals("Invalid response", securedResponseMessage, getMessage((SoapMessage) context.getResponse()));
	}

	@Test
	public void testHandleCustomSecurityEngine() {
		WSSecurityEngine engine = new WSSecurityEngine();
		Wss4jSecurityInterceptor interceptor = new Wss4jSecurityInterceptor(engine);
		assertEquals(engine, ReflectionTestUtils.getField(interceptor, "securityEngine"));
	}

}
