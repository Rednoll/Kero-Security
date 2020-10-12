package com.kero.security.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.kero.security.core.scheme.AccessProxy;

public class AdaptiveProxyWrapperTest {

	@Test
	public void createProxyClass() {
		
		AdaptiveProxyWrapper wrapper = new AdaptiveProxyWrapper(TestClass.class);
		
		Class<?> proxyClass = wrapper.createProxyClass();
	
		assertEquals(proxyClass.getSuperclass(), TestClassParent.class);
		
		List<Class<?>> interfaces = Arrays.asList(proxyClass.getInterfaces());
		
		assertEquals(interfaces.size(), 2);
		assertTrue(interfaces.contains(AccessProxy.class));
		assertTrue(interfaces.contains(TestInterface.class));
	}
	
	public static final class TestClass extends TestClassParent implements TestInterface {}
	
	public static interface TestInterface {}

	public static class TestClassParent implements ParentInterface {}
	
	public static interface ParentInterface {}
}
