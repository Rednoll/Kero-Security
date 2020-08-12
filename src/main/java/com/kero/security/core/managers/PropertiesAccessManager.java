package com.kero.security.core.managers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;

public class PropertiesAccessManager {

	private List<Property> properties;
	private KeroAccessManager manager;
	
	public PropertiesAccessManager(KeroAccessManager manager, List<Property> properties) {
	
		this.manager = manager;
		this.properties = properties;
	}
	
	public PropertiesAccessManager defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public PropertiesAccessManager defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public PropertiesAccessManager defaultRule(AccessRule rule) {
		
		for(Property property : properties) {
			
			new SinglePropertyAccessManager(this.manager, property).defaultRule(rule);
		}
		
		return this;
	}
	
	public PropertiesAccessManager grantFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		setAccessible(roles, true);
		
		return this;
	}
	
	public PropertiesAccessManager denyFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(manager.getOrCreateRole(name));
		}
		
		setAccessible(roles, false);
		
		return this;
	}
	
	public PropertiesAccessManager setAccessible(Set<Role> roles, boolean accessible) {
		
		for(Property property : properties) {
			
			new SinglePropertyAccessManager(this.manager, property).setAccessible(roles, accessible);
		}
		
		return this;
	}
}
