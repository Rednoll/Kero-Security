package com.kero.security.core.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.definition.configurator.AccessSchemeDefinitionConfigurator;
import com.kero.security.lang.provider.KsdlProvider;
import com.kero.security.lang.provider.TextualProvider;
import com.kero.security.lang.provider.resource.KsdlTextResource;

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
	
	@Test
	public void mainProvider_PreloadTest() {
		
		KsdlTextResource resource1 = Mockito.mock(KsdlTextResource.class);
		KsdlTextResource resource2 = Mockito.mock(KsdlTextResource.class);
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addKsdlProvider(new TextualProvider(resource1));
			agent.addKsdlProvider(new TextualProvider(resource2));
	
		agent.preloadMainProvider();
		
		agent.getMainProvider().getRoots();
		agent.getMainProvider().getRoots();
		
		Mockito.verify(resource1, Mockito.times(1)).getRawText();
		Mockito.verify(resource2, Mockito.times(1)).getRawText();
	}
	
	public static class TestClass {}
}
