package com.kero.security.core.agent;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.agent.configuration.KeroAccessAgentConfigurator;
import com.kero.security.lang.provider.KsdlProvider;
import com.kero.security.lang.provider.TextualProvider;

public class KeroAccessAgentFactoryImplTest {

	@Test
	public void test() {
		
		KeroAccessAgentConfigurator configurator = Mockito.mock(KeroAccessAgentConfigurator.class);
		
		KeroAccessAgentFactoryImpl factory = new KeroAccessAgentFactoryImpl();
			factory.addConfigurator(configurator);
	
		factory.create();
			
		Mockito.verify(configurator, Mockito.times(1)).configure(Mockito.any());
	}
	
	@Test
	public void testPreload() {
		
		TextualProvider provider = Mockito.mock(TextualProvider.class);
		
		KeroAccessAgentFactory factory = new KeroAccessAgentFactoryImpl.Builder().setMainProviderPreloading(true).build();
		
		factory.addConfigurator(new KeroAccessAgentConfigurator() {
			
			@Override
			public void configure(KeroAccessAgent agent) {
				
				agent.addKsdlProvider(provider);
			}
		});
		
		KeroAccessAgent agent = factory.create();
	
		Mockito.verify(provider, Mockito.times(1)).preloadResource();
	}
}
