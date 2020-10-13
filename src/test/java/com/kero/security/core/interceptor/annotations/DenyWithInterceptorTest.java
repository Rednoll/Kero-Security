package com.kero.security.core.interceptor.annotations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.interceptor.DenyInterceptorBase;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class DenyWithInterceptorTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
	
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		assertEquals(scheme.getLocalProperty("name").getInterceptors().get(0).getClass(), Interceptor.class);
		assertTrue(scheme.getLocalProperty("name").getDenyRoles().contains(agent.getRole("OWNER")));
		
		assertEquals(scheme.getLocalProperty("text").getDefaultInterceptor().getClass(), DefaultInterceptor.class);
		assertEquals(scheme.getLocalProperty("text").getDefaultAccess(), Access.DENY);
	}
	
	public static class TestClass {
		
		@DenyWithInterceptor(value = Interceptor.class, roles = "OWNER")
		private String name;
		
		@DenyWithInterceptor(DefaultInterceptor.class)
		private String text;
	
		public String getName() {
			
			return this.name;
		}
		
		public String getText() {
			
			return this.text;
		}
	}
	
	public static class Interceptor extends DenyInterceptorBase {

		@Override
		public Object intercept(Object original, Object[] args) {
		
			return "Intercepted";
		}		
	}
	
	public static class DefaultInterceptor extends DenyInterceptorBase {
		
		@Override
		public Object intercept(Object original, Object[] args) {
		
			return "Intercepted";
		}	
	}
}
