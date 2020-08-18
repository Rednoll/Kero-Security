package com.kero.security.core.managers;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.property.Property;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.scheme.AccessScheme;

public class AccessSchemeManager {

	private AccessScheme scheme;
	private KeroAccessManager manager;
	
	public AccessSchemeManager(KeroAccessManager manager, AccessScheme scheme) {
		
		this.manager = manager;
		this.scheme = scheme;
	}
	
	public AccessSchemeManager defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public AccessSchemeManager defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public AccessSchemeManager defaultRule(AccessRule rule) {
		
		scheme.setDefaultRule(rule);
	
		return this;
	}
	
	public PropertiesManager properties(String... propertyNames) {
		
		List<Property> properties = new LinkedList<>();
		
		for(String name : propertyNames) {
			
			properties.add(this.scheme.getOrCreateLocalProperty(name));
		}
		
		return properties(properties);
	}
	
	public PropertiesManager properties(List<Property> properties) {
		
		return new PropertiesManager(this, properties);
	}
	
	
	public SinglePropertyManager property(String propertyName) {
		
		return property(this.scheme.getOrCreateLocalProperty(propertyName));
	}
	
	public SinglePropertyManager property(Property property) {
	
		return new SinglePropertyManager(this, property);
	}
	

	public AccessSchemeManager disableInherit() {
		
		return inherit(false);
	}

	public AccessSchemeManager enableInherit() {
		
		return inherit(true);
	}
	
	public AccessSchemeManager inherit(boolean inherit) {
		
		scheme.setInherit(inherit);
		return this;
	}
	
	public KeroAccessManager getManager() {
		
		return this.manager;
	}
	
	public AccessScheme getScheme() {
		
		return this.scheme;
	}
}
