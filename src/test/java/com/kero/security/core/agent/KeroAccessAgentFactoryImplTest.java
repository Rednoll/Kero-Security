package com.kero.security.core.agent;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.core.agent.configuration.KeroAccessAgentConfigurator;

public class KeroAccessAgentFactoryImplTest {

	@Test
	public void test() {
		
		KeroAccessAgentConfigurator configigurator = Mockito.mock(KeroAccessAgentConfigurator.class);
		
		KeroAccessAgentFactoryImpl factory = new KeroAccessAgentFactoryImpl();
			factory.addConfigurator(configigurator);
	
		factory.create();
			
		Mockito.verify(configigurator, Mockito.times(1)).configure(Mockito.any());
	}
}
