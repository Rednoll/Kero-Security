package com.kero.security.core.type;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.core.property.PropertyImpl;
import com.kero.security.core.rules.AccessRule;

public abstract class ProtectedTypeBase implements ProtectedType {

	protected Class<?> type;
	
	protected Map<String, Property> properties = new HashMap<>();
	
	protected AccessRule defaultRule;

	protected KeroAccessManager accessManager;
	
	public ProtectedTypeBase() {}
	
	public ProtectedTypeBase(KeroAccessManager accessManager, Class<?> type, AccessRule defaultRule) throws Exception {
		
		this.accessManager = accessManager;
		this.type = type;
		this.defaultRule = defaultRule;
	}
	@Override
	public void setDefaultRule(AccessRule defaulRule) {
		
		this.defaultRule = defaulRule;
	}

	@Override
	public boolean hasDefaultRule() {
		
		return getDefaultRule() != null;
	}

	@Override
	public AccessRule getDefaultRule() {
		
		return this.defaultRule;
	}
	
	public Property createProperty(String name, AccessRule defaultRule) {
		
		Property property = new PropertyImpl(name, defaultRule);
		
		properties.put(name, property);
		
		return property;
	}
	
	@Override
	public boolean hasProperty(String name) {
		
		return properties.containsKey(name);
	}
	
	@Override
	public Property getProperty(String name) {
		
		return properties.get(name);
	}
	
	@Override
	public Set<Property> getProperties() {
	
		return new HashSet<>(properties.values());
	}
	
	@Override
	public Class<?> getTypeClass() {
		
		return this.type;
	}
}
