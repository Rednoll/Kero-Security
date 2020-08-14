package com.kero.security.core;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.managers.KeroAccessManagerImpl;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.type.ProtectedType;

public class MainTest {

	@Test
	public void test() {

		KeroAccessManager manager = new KeroAccessManagerImpl();

		manager
			.type(TestInterface.class)
				.property("text")
					.denyWithInterceptor((obj)-> {
					
						return "You not have access!";
					}, "FRIEND");
		manager
			.type(TestObject.class)
				.defaultGrant()
				.property("text")
					.denyFor("FRIEND");

		ProtectedType protectedType = manager.getType(TestObject.class);
	
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
	}
}
