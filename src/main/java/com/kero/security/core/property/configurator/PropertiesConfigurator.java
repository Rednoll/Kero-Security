package com.kero.security.core.property.configurator;

import java.util.List;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.scheme.configurator.CodeAccessSchemeConfigurator;

public class PropertiesConfigurator {

	private List<Property> properties;
	private CodeAccessSchemeConfigurator schemeConf;
	
	public PropertiesConfigurator(CodeAccessSchemeConfigurator schemeConf, List<Property> properties) {
	
		this.schemeConf = schemeConf;
		this.properties = properties;
	}
	
	public CodeAccessSchemeConfigurator cd() {
		
		return schemeConf;
	}
	
	public PropertiesConfigurator defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public PropertiesConfigurator defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public PropertiesConfigurator defaultRule(AccessRule rule) {
		
		for(Property property : properties) {
			
			new SinglePropertyConfigurator(this.schemeConf, property).defaultRule(rule);
		}
		
		return this;
	}
	
	public PropertiesConfigurator grantFor(String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		setAccessible(roles, true);
		
		return this;
	}
	
	public PropertiesConfigurator denyFor(String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		setAccessible(roles, false);
		
		return this;
	}
	
	public PropertiesConfigurator setAccessible(Set<Role> roles, boolean accessible) {
		
		for(Property property : properties) {
			
			new SinglePropertyConfigurator(schemeConf, property).setAccessible(roles, accessible);
		}
		
		return this;
	}
}
