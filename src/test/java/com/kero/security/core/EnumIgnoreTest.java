package com.kero.security.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;

public class EnumIgnoreTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
		
		agent.getKeroAccessConfigurator()
			.scheme(EnumTestObj.class)
				.defaultGrant();
		
		EnumTestObj obj = agent.protect(new EnumTestObj());
		
		assertEquals(obj.getEnum(), TestEnum.FIRST);
	}
	
	public static class EnumTestObj {
		
		private TestEnum testEnum = TestEnum.FIRST;
		
		public TestEnum getEnum() {

			return this.testEnum;
		}
	}
	
	public static enum TestEnum {
		
		FIRST, SECOND;
	}
}
