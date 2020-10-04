package com.kero.security.core;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.annotations.DefaultGrant;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.interceptor.DenyInterceptorBase;
import com.kero.security.core.interceptor.annotations.DenyWithInterceptor;

public class AnnotationsTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
		
		TestAnnotatedObject obj = agent.protect(new TestAnnotatedObject("test_default_text"), "FRIEND");
	
		System.out.println("obj: "+obj.getText());
	}

	public static interface TestAnnotatedInterface {
		
		@DenyWithInterceptor(value = TestInterceptor.class, roles = "FRIEND")
		public String getText();
	}
	
	@DefaultGrant
	public static class TestAnnotatedObject implements TestAnnotatedInterface {

		private String text;
	
		public TestAnnotatedObject() {}
		
		public TestAnnotatedObject(String text) {
			
			this.text = text;
		}
		
		public String getText() {
			
			return this.text;
		}
	}
	
	public static class TestInterceptor extends DenyInterceptorBase {

		@Override
		public Object intercept(Object obj) {
			
			return "Intercepted!";
		}
	}
}
