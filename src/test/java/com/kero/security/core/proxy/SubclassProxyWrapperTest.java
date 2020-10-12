package com.kero.security.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class SubclassProxyWrapperTest {

	@Test
	public void createProxyClass() {
		
		SubclassProxyWrapper wrapper = new SubclassProxyWrapper(TestClass.class);
	
		Class<?> proxyClass = wrapper.createProxyClass();
		
		assertEquals(proxyClass.getSuperclass(), TestClass.class);
	}
	
	public static class TestClass {}
}
