package com.kero.security.managers;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.property.Property;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;

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
			
			name = manager.extractName(name);
			
			properties.add(this.scheme.getOrCreateLocalProperty(name));
		}
		
		return properties(properties);
	}
	
	public PropertiesManager properties(List<Property> properties) {
		
		return new PropertiesManager(this, properties);
	}
	
	
	public SinglePropertyManager property(String propertyName) {
		
		propertyName = manager.extractName(propertyName);
		
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
		
		this.scheme.setInherit(inherit);
		return this;
	}
	
	public AccessSchemeManager proxy(Class<? extends AccessProxy> proxy) {
		
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
