package com.kero.security.core;

import org.junit.jupiter.api.Test;

import com.kero.security.core.interceptor.DenyInterceptorBase;
import com.kero.security.core.interceptor.annotations.DenyWithInterceptor;
import com.kero.security.core.rules.annotations.DefaultGrant;

public class AnnotationsTest {

	@Test
	public void test() {
		
		KeroAccessManager manager = new KeroAccessManagerImpl();
		
		TestAnnotatedObject obj = manager.protect(new TestAnnotatedObject("test_default_text"), "FRIEND");
	
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
