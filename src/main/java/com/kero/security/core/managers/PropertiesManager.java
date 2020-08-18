package com.kero.security.core.managers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;

public class PropertiesManager {

	private List<Property> properties;
	private AccessSchemeManager schemeManager;
	
	public PropertiesManager(AccessSchemeManager schemeManager, List<Property> properties) {
	
		this.schemeManager = schemeManager;
		this.properties = properties;
	}
	
	public PropertiesManager defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public PropertiesManager defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public PropertiesManager defaultRule(AccessRule rule) {
		
		for(Property property : properties) {
			
			new SinglePropertyManager(this.schemeManager, property).defaultRule(rule);
		}
		
		return this;
	}
	
	public PropertiesManager grantFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(schemeManager.getManager().getOrCreateRole(name));
		}
		
		setAccessible(roles, true);
		
		return this;
	}
	
	public PropertiesManager denyFor(String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(schemeManager.getManager().getOrCreateRole(name));
		}
		
		setAccessible(roles, false);
		
		return this;
	}
	
	public PropertiesManager setAccessible(Set<Role> roles, boolean accessible) {
		
		for(Property property : properties) {
			
			new SinglePropertyManager(schemeManager, property).setAccessible(roles, accessible);
		}
		
		return this;
	}
}
