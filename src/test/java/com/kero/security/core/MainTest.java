package com.kero.security.core;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

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
			.properties("text")
			.denyFor("COMMON", "ADMIN");
		
		manager
			.type(TestObject.class)
			.properties("text")
			.grantFor("OWNER", "ADMIN");
		
		manager
			.type(TestObject2.class)
			.properties("text")
			.denyFor("OWNER");
		
		ProtectedType protectedType = manager.getType(TestObject2.class);
	
		Map<Property, List<AccessRule>> rules = protectedType.collectRules();
		
		for(Entry<Property, List<AccessRule>> entry : rules.entrySet()) {
			
			Property property = entry.getKey();
			List<AccessRule> propRules = entry.getValue();
			
			for(AccessRule rule : propRules) {
			
				StringBuilder builder = new StringBuilder();
				
				for(Role role : rule.getRoles()) {
					
					builder.append(role.getName()+" ");
				}
				
				System.out.println("property: \""+property.getName()+"\" rule("+(rule.isAllower() ? "allower" : "disallower")+"): ["+builder.toString().trim()+"]");
			}
		}
	}
}
