package com.kero.security.core.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.definition.configurator.AccessSchemeDefinitionConfigurator;

public class KeroAccessAgentImplTest {

	@Test
	public void typeNameBinding() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.setTypeName("TestName", TestClass.class);
	
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		assertEquals(scheme.getName(), "TestName");
	}
	
	@Test
	public void accessSchemeDefinitionConfiguratorApply() {
		
		AccessSchemeDefinitionConfigurator configMock = Mockito.mock(AccessSchemeDefinitionConfigurator.class);
	
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addDefinitionConfigurator(configMock);
	
		agent.getOrCreateScheme(TestClass.class);
		
		Mockito.verify(configMock, Mockito.times(1)).configure(Mockito.any());
	}
	
	public static class TestClass {}
}
