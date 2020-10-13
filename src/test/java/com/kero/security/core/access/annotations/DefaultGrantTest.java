package com.kero.security.core.access.annotations;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class DefaultGrantTest {

	@Test
	public void onTypeLevelTest() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
	
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
		
		assertEquals(scheme.getDefaultAccess(), Access.GRANT);
	}
	
	@Test
	public void onPropLevelTest() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));

		AccessScheme scheme = agent.getOrCreateScheme(TestClassProp.class);
	
		assertEquals(scheme.getLocalProperty("name").getDefaultAccess(), Access.GRANT);
	}
	
	public static class TestClassProp {
		
		@DefaultGrant
		private String name;
		
		public String getName() {
			
			return this.name;
		}
	}
	
	@DefaultGrant
	public static class TestClass {}
}
