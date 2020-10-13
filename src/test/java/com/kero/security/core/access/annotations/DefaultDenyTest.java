package com.kero.security.core.access.annotations;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class DefaultDenyTest {

	@Test
	public void onTypeLevelTest() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
	
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
		
		assertEquals(scheme.getDefaultAccess(), Access.DENY);
	}
	
	@Test
	public void onPropLevelTest() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));

		AccessScheme scheme = agent.getOrCreateScheme(TestClassProp.class);
	
		assertEquals(scheme.getLocalProperty("name").getDefaultAccess(), Access.DENY);
	}
	
	public static class TestClassProp {
		
		@DefaultDeny
		private String name;
	}
	
	@DefaultDeny
	public static class TestClass {}
}
