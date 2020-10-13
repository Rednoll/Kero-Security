package com.kero.security.core.interceptor.annotations;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.interceptor.DenyInterceptorBase;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class AddDenyInterceptorTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
	
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		assertEquals(scheme.getLocalProperty("name").getInterceptors().get(0).getClass(), TestInterceptor.class);
		assertEquals(scheme.getLocalProperty("text").getDefaultInterceptor().getClass(), DefaultTestInterceptor.class);
	}
	
	public static class TestClass {
		
		@AddDenyInterceptor(value = TestInterceptor.class, roles = "OWNER")
		private String name;
		
		@AddDenyInterceptor(DefaultTestInterceptor.class)
		private String text;
	}
	
	public static class TestInterceptor extends DenyInterceptorBase {
		
		@Override
		public Object intercept(Object original, Object[] args) {
			
			return "intercepted";
		}
	}

	public static class DefaultTestInterceptor extends DenyInterceptorBase {

		@Override
		public Object intercept(Object original, Object[] args) {
			
			return "default intercepted";
		}
	}
}
