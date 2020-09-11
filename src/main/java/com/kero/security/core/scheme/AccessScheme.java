package com.kero.security.core.scheme;

import java.util.Map;
import java.util.Set;

import com.kero.security.core.DefaultRuleOwner;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;

public interface AccessScheme extends DefaultRuleOwner {

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
	
	public Class<?> getTypeClass();
	
	public String getAliase();
	
	public KeroAccessAgent getAgent();
}
