package com.kero.security.core.managers;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.property.Property;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.rules.SimpleAccessRule;
import com.kero.security.core.type.ProtectedType;

public class ObjectTypeAccessManager {

	private ProtectedType managedType;
	
	public ObjectTypeAccessManager(ProtectedType managedType) {
		
		this.managedType = managedType;
	}
	
	public ObjectTypeAccessManager defaultGrant() {
		
		return defaultRule(SimpleAccessRule.GRANT_ALL);
	}
	
	public ObjectTypeAccessManager defaultDeny() {
		
		return defaultRule(SimpleAccessRule.DENY_ALL);
	}
	
	public ObjectTypeAccessManager defaultRule(AccessRule rule) {
		
		managedType.setDefaultRule(rule);
	
		return this;
	}
	
	public PropertiesAccessManager properties(String... propertyNames) {
		
		List<Property> properties = new LinkedList<>();
		
		for(String name : propertyNames) {
			
			properties.add(this.managedType.getOrCreateProperty(name, managedType.getDefaultRule()));
		}
		
		return properties(properties);
	}
	
	public SinglePropertyAccessManager property(String propertyName) {
		
		return property(this.managedType.getOrCreateProperty(propertyName, managedType.getDefaultRule()));
	}
	
	public SinglePropertyAccessManager property(Property property) {
	
		return new SinglePropertyAccessManager(property);
	}
	
	public PropertiesAccessManager properties(List<Property> properties) {
		
		return new PropertiesAccessManager(properties);
	}
	
	public ProtectedType getManagedType() {
		
		return this.managedType;
	}
}
