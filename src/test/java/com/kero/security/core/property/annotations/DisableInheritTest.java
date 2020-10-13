package com.kero.security.core.property.annotations;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class DisableInheritTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
		
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		assertFalse(scheme.isInherit());
	}
	
	@DisableInherit
	public static class TestClass {}
}
