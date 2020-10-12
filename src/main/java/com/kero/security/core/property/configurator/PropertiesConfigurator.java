package com.kero.security.core.property.configurator;

import java.util.List;
import java.util.Set;

import com.kero.security.core.access.Access;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
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
		
		return defaultAccess(Access.GRANT);
	}
	
	public PropertiesConfigurator defaultDeny() {
		
		return defaultAccess(Access.DENY);
	}
	
	public PropertiesConfigurator defaultAccess(Access access) {
		
		for(Property property : properties) {
			
			new SinglePropertyConfigurator(this.schemeConf, property).defaultAccess(access);
		}
		
		return this;
	}
	
	public PropertiesConfigurator grantFor(String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		for(Property property : properties) {
			
			new SinglePropertyConfigurator(schemeConf, property).grantFor(roles);
		}

		return this;
	}
	
	public PropertiesConfigurator denyFor(String... roleNames) {
		
		Set<Role> roles = schemeConf.getAgent().getOrCreateRole(roleNames);
		
		for(Property property : properties) {
			
			new SinglePropertyConfigurator(schemeConf, property).denyFor(roles);
		}
		
		return this;
	}
}
