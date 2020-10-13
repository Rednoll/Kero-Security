package com.kero.security.core.protector.storage;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;

public class KeroProtectorStorageImplTest {

	@Test
	public void createProtector() {
	
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
		
		KeroProtectorStorageImpl storage = new KeroProtectorStorageImpl();
	
		storage.createProtector(scheme);
		
		assertThrows(RuntimeException.class, ()-> {storage.createProtector(scheme);});
	}
	
	public static class TestClass {}
}
