package com.kero.security.core.type;

import java.util.Map;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public interface ProtectedType {

	public Map<String, Property> collectRules();
	public void collectRules(Map<String, Property> complexProperties, Map<String, Set<Role>> processedRoles);
	
	public default Property getOrCreateProperty(String name) {
		
		if(hasProperty(name)) {
			
			return getProperty(name);
		}
		else {
			
			return createProperty(name);
		}
	}
	
	public Property createProperty(String name);
	public boolean hasProperty(String name);
	public Property getProperty(String name);
	public Set<Property> getProperties();

	public void setDefaultRule(AccessRule defaulRule);
	public boolean hasDefaultRule();
	public AccessRule getDefaultRule();
	
	public Class<?> getTypeClass();
}
