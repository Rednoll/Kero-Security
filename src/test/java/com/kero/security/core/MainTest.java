package com.kero.security.core;

import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.configurator.KeroAccessConfigurator;

public class MainTest {

	@Test
	public void test() {

		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();

		KeroAccessConfigurator configurator = agent.getKeroAccessConfigurator();
		
		configurator
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.defaultGrant();
		
		TestObject prot = agent.protect(new TestObject("test text!"));
		
		prot.getText();
		
		/*
		agent.getKeroAccessConfigurator()
			.scheme(TestInterface.class)
				.property("text")
					.denyWithInterceptor((obj)-> {
					
						return "You not have access!";
					}, "FRIEND");
		
		agent.getKeroAccessConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.denyFor("FRIEND")
					.grantFor("OWNER");

		agent.getKeroAccessConfigurator()
			.scheme(TestObjectDeep.class)
				.defaultDeny()
				.property("testObject")
					.grantFor("OWNER");
		
		TestObjectDeep deep = agent.protect(new TestObjectDeep(new TestObject("test text!!")), "OWNER");
		 */
	}

	public static class TestObjectDeep {
		
		private Map<String, TestObject> objects = new TreeMap<>();

		private TestObject testObject = null;
		
		public TestObjectDeep() {
			
			objects.put("kek", new TestObject("collection object"));
		}
		
		public TestObjectDeep(TestObject testObject) {
			this();
			
			this.testObject = testObject;
		}
		
		public Map<String, TestObject> getObjects() {
		
			return this.objects;
		}
		
		public TestObject getTestObject() {
			
			return this.testObject;
		}
	}
}
