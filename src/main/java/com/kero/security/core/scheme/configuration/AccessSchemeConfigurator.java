package com.kero.security.core.scheme.configuration;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;

public class AccessSchemeConfigurator {

	private AccessScheme scheme;
	private KeroAccessManager manager;
	
	public AccessSchemeConfigurator(KeroAccessManager manager, AccessScheme scheme) {
		
		this.manager = manager;
		this.scheme = scheme;
	}
	
	public AccessSchemeConfigurator defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public AccessSchemeConfigurator defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public AccessSchemeConfigurator defaultRule(AccessRule rule) {
		
		scheme.setDefaultRule(rule);
	
		return this;
	}
	
	public PropertiesConfigurator properties(String... propertyNames) {
		
		List<Property> properties = new LinkedList<>();
		
		for(String name : propertyNames) {
			
			name = manager.extractName(name);
			
			properties.add(this.scheme.getOrCreateLocalProperty(name));
		}
		
		return properties(properties);
	}
	
	public PropertiesConfigurator properties(List<Property> properties) {
		
		return new PropertiesConfigurator(this, properties);
	}
	
	
	public SinglePropertyConfigurator property(String propertyName) {
		
		propertyName = manager.extractName(propertyName);
		
		return property(this.scheme.getOrCreateLocalProperty(propertyName));
	}
	
	public SinglePropertyConfigurator property(Property property) {
	
		return new SinglePropertyConfigurator(this, property);
	}
	

	public AccessSchemeConfigurator disableInherit() {
		
		return inherit(false);
	}

	public AccessSchemeConfigurator enableInherit() {
		
		return inherit(true);
	}
	
	public AccessSchemeConfigurator inherit(boolean inherit) {
		
		this.scheme.setInherit(inherit);
		return this;
	}
	
	public AccessSchemeConfigurator proxy(Class<? extends AccessProxy> proxy) {
		
		if(!(this.scheme instanceof ClassAccessScheme)) throw new RuntimeException("Can't set proxy class to not CLASS scheme!");
	
		((ClassAccessScheme) this.scheme).setProxyClass(proxy);
		
		return this;
	}
	
	public KeroAccessManager getManager() {
		
		return this.manager;
	}
	
	public AccessScheme getScheme() {
		
		return this.scheme;
	}
}
