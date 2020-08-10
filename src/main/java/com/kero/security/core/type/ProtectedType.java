package com.kero.security.core.type;

import java.lang.reflect.Method;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public interface ProtectedType {

	public void setDefaultRule(AccessRule defaulRule);
	public boolean hasDefaultRule();
	public AccessRule getDefaultRule();
	
	public Object tryInvoke(Object target, Method method, Object[] args, Set<Role> roles) throws Exception;
	
	public default Property getOrCreateProperty(String name, AccessRule defaultRule) {
		
		if(hasProperty(name)) {
			
			return getProperty(name);
		}
		else {
			
			return createProperty(name, defaultRule);
		}
	}
	
	public Property createProperty(String name, AccessRule defaultRule);
	public boolean hasProperty(String name);
	public Property getProperty(String name);
	public Set<Property> getProperties();

	public Class<?> getTypeClass();
}
