package com.kero.security.core.managers;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.property.Property;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.AccessRuleImpl;
import com.kero.security.core.type.ProtectedType;

public class ObjectTypeAccessManager {

	private ProtectedType managedType;
	private KeroAccessManager manager;
	
	public ObjectTypeAccessManager(KeroAccessManager manager, ProtectedType managedType) {
		
		this.manager = manager;
		this.managedType = managedType;
	}
	
	public ObjectTypeAccessManager defaultGrant() {
		
		return defaultRule(AccessRuleImpl.GRANT_ALL);
	}
	
	public ObjectTypeAccessManager defaultDeny() {
		
		return defaultRule(AccessRuleImpl.DENY_ALL);
	}
	
	public ObjectTypeAccessManager defaultRule(AccessRule rule) {
		
		managedType.setDefaultRule(rule);
	
		return this;
	}
	
	public PropertiesAccessManager properties(String... propertyNames) {
		
		List<Property> properties = new LinkedList<>();
		
		for(String name : propertyNames) {
			
			properties.add(this.managedType.getOrCreateProperty(name));
		}
		
		return properties(properties);
	}
	
	public PropertiesAccessManager properties(List<Property> properties) {
		
		return new PropertiesAccessManager(this.manager, properties);
	}
	
	
	public SinglePropertyAccessManager property(String propertyName) {
		
		return property(this.managedType.getOrCreateProperty(propertyName));
	}
	
	public SinglePropertyAccessManager property(Property property) {
	
		return new SinglePropertyAccessManager(this.manager, property);
	}
	

	public ObjectTypeAccessManager disableInherit() {
		
		return inherit(false);
	}

	public ObjectTypeAccessManager enableInherit() {
		
		return inherit(true);
	}
	
	public ObjectTypeAccessManager inherit(boolean inherit) {
		
		managedType.setInherit(inherit);
		return this;
	}
	
	public ProtectedType getManagedType() {
		
		return this.managedType;
	}
}
