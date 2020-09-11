package com.kero.security.core;

import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentImpl;
import com.kero.security.core.role.annotations.PropagateRole;

public class MainTest {

	@Test
	public void test() {

		KeroAccessAgent agent = new KeroAccessAgentImpl();

		agent.getConfigurator()
			.scheme(TestInterface.class)
				.property("text")
					.denyWithInterceptor((obj)-> {
					
						return "You not have access!";
					}, "FRIEND");
		
		agent.getConfigurator()
			.scheme(TestObject.class)
				.defaultDeny()
				.property("text")
					.denyFor("FRIEND")
					.grantFor("OWNER");

		agent.getConfigurator()
			.scheme(TestObjectDeep.class)
				.defaultDeny()
				.property("testObject")
					.grantFor("OWNER");
		
		TestObjectDeep deep = agent.protect(new TestObjectDeep(new TestObject("test text!!")), "OWNER");
		
		System.out.println("text: "+deep.getTestObject().getText());
		
		//TEST IN IN
		
		/*
		Set<Property> properties = protectedType.getProperties();
		
		for(Property property : properties) {
			
			AccessRule defaultRule = property.getDefaultRule();
			
			if(defaultRule != null) {
				
				StringBuilder builder = new StringBuilder();
				
				for(Role role : defaultRule.getRoles()) {
					
					builder.append(role.getName()+" ");
				}
				
				System.out.println("property: \""+property.getName()+"\" default rule("+(defaultRule.isAllower() ? "allower" : "disallower")+"): ["+builder.toString().trim()+"]");
			}
			
			List<AccessRule> propRules = property.getRules();
			
			for(AccessRule rule : propRules) {
			
				StringBuilder builder = new StringBuilder();
				
				for(Role role : rule.getRoles()) {
					
					builder.append(role.getName()+" ");
				}
				
				System.out.println("property: \""+property.getName()+"\" rule("+(rule.isAllower() ? "allower" : "disallower")+"): ["+builder.toString().trim()+"]");
			}
		}
		
		for(int i = 0; i < 100000; i++) {
			
			manager.protect(new TestObject2("test12"), "COMMON", "OWNER").getText();
		}
		
		System.out.println(manager.protect(new TestObject2("test12"), "FRIEND").getText());
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
