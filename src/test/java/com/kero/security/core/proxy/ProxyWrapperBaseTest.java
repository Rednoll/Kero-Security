package com.kero.security.core.proxy;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.scheme.AccessProxy;

public class ProxyWrapperBaseTest {

	@Test
	public void createProxyClass_OneCall() {
		
		ProxyWrapperBase mock = Mockito.mock(ProxyWrapperBase.class, Mockito.CALLS_REAL_METHODS);
		Mockito.doReturn(TestProxyClass.class).when(mock).createProxyClass();

		mock.wrap(null, null);
		mock.wrap(null, null);
		
		Mockito.verify(mock, Mockito.times(1)).createProxyClass();
	}
	
	public static class TestProxyClass implements AccessProxy {

		public TestProxyClass(Object obj, PreparedAccessConfiguration pac) {
			
		}
		
		@Override
		public Object getOriginal() {
			
			return null;
		}
	}
}
