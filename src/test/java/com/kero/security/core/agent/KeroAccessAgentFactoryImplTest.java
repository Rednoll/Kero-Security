package com.kero.security.core.agent;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.agent.configurator.KeroAccessAgentConfigurator;

public class KeroAccessAgentFactoryImplTest {

	@Test
	public void test() {
		
		KeroAccessAgentConfigurator configurator = Mockito.mock(KeroAccessAgentConfigurator.class);
		
		KeroAccessAgentFactoryImpl factory = new KeroAccessAgentFactoryImpl();
			factory.addConfigurator(configurator);
	
		factory.create();
			
		Mockito.verify(configurator, Mockito.times(1)).configure(Mockito.any());
	}
}
