package com.kero.security.core.scheme;

import java.util.Map;
import java.util.Set;

import com.kero.security.core.property.Property;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.managers.KeroAccessManager;

public interface AccessScheme {

	public void collectProperties(Map<String, Property> complexProperties);
	
	public default Property getOrCreateLocalProperty(String name) {
		
		if(hasLocalProperty(name)) {
			
			return getLocalProperty(name);
		}
		else {
			
			return createLocalProperty(name);
		}
	}
	
	public void setInherit(boolean i);
	public boolean isInherit();
	
	public Property createLocalProperty(String name);
	public boolean hasLocalProperty(String name);
	public Property getLocalProperty(String name);
	public Set<Property> getLocalProperties();

	public Set<Property> getProperties();

	public void setDefaultRule(AccessRule defaulRule);
	public boolean hasDefaultRule();
	public AccessRule getDefaultRule();
	
	public Class<?> getTypeClass();
	
	public KeroAccessManager getManager();
}
