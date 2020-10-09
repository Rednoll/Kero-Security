package com.kero.security.core.scheme.configurator;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.access.annotations.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.property.configurator.PropertiesConfigurator;
import com.kero.security.core.property.configurator.SinglePropertyConfigurator;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.ClassAccessScheme;

public class CodeAccessSchemeConfigurator {

	private AccessScheme scheme;
	private KeroAccessAgent agent;
	
	public CodeAccessSchemeConfigurator(KeroAccessAgent agent, AccessScheme scheme) {
		
		this.agent = agent;
		this.scheme = scheme;
	}
	
	public CodeAccessSchemeConfigurator defaultGrant() {
		
		return defaultRule(Access.GRANT);
	}
	
	public CodeAccessSchemeConfigurator defaultDeny() {
		
		return defaultRule(Access.DENY);
	}
	
	public CodeAccessSchemeConfigurator defaultRule(Access access) {
		
		scheme.setDefaultAccess(access);
	
		return this;
	}
	
	public PropertiesConfigurator properties(String... propertyNames) {
		
		List<Property> properties = new LinkedList<>();
		
		for(String name : propertyNames) {
			
			name = agent.extractPropertyName(name);
			
			properties.add(this.scheme.getOrCreateLocalProperty(name));
		}
		
		return properties(properties);
	}
	
	public PropertiesConfigurator properties(List<Property> properties) {
		
		return new PropertiesConfigurator(this, properties);
	}
	
	
	public SinglePropertyConfigurator property(String propertyName) {
		
		propertyName = agent.extractPropertyName(propertyName);
		
		return property(this.scheme.getOrCreateLocalProperty(propertyName));
	}
	
	public SinglePropertyConfigurator property(Property property) {
	
		return new SinglePropertyConfigurator(this, property);
	}
	

	public CodeAccessSchemeConfigurator disableInherit() {
		
		return inherit(false);
	}

	public CodeAccessSchemeConfigurator enableInherit() {
		
		return inherit(true);
	}
	
	public CodeAccessSchemeConfigurator inherit(boolean inherit) {
		
		this.scheme.setInherit(inherit);
		return this;
	}
	
	/*
	public CodeAccessSchemeConfigurator proxy(Class<? extends AccessProxy> proxy) {
		
		if(!(this.scheme instanceof ClassAccessScheme)) throw new RuntimeException("Can't set proxy class to not CLASS scheme!");
	
		((ClassAccessScheme) this.scheme).setProxyClass(proxy);
		
		return this;
	}
	*/
	
	public KeroAccessAgent getAgent() {
		
		return this.agent;
	}
	
	public AccessScheme getScheme() {
		
		return this.scheme;
	}
}
