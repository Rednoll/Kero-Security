package com.kero.security.core;

import java.util.List;
import java.util.Map;

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
				.defaultDeny()
				.property("text")
					.defaultGrant()
					.denyFor("FRIEND")
					.defaultInterceptor((obj)-> {
					
						return "You not have access!";
					});
		manager
			.type(TestObject.class)
				.property("text")
					.grantFor("COMMON", "OWNER", "ADMIN")
					.defaultInterceptor((obj)-> {
						
						return "You not have access! (Overrided by TestObject.class)";
					});
			
		manager
			.type(TestObject2.class)
				.property("text")
					.denyFor("COMMON", "ADMIN");
		
		ProtectedType protectedType = manager.getType(TestObject2.class);
	
		Map<String, Property> properties = protectedType.collectRules();
		
		for(Property property : properties.values()) {
			
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
		
		System.out.println(manager.protect(new TestObject2("test12"), "COMMON").getText());
	}
}
