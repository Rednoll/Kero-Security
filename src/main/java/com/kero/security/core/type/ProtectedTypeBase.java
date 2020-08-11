package com.kero.security.core.type;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.property.Property;
import com.kero.security.core.property.PropertyImpl;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public abstract class ProtectedTypeBase implements ProtectedType {

	protected Class<?> type;
	
	protected AccessRule defaultRule;
	
	protected Map<String, Property> properties = new HashMap<>();
	
	protected KeroAccessManager manager;
	
	public ProtectedTypeBase() {
		
	}
	
	public ProtectedTypeBase(KeroAccessManager manager, Class<?> type, AccessRule defaultRule) {
		
		this.manager = manager;
		this.type = type;
		this.defaultRule = defaultRule;
	}
	
	@Override
	public Map<String, Property> collectRules() {
	
		Map<String, Property> complexProperties = new HashMap<>();
		Map<String, Set<Role>> processedRoles = new HashMap<>();
		
		collectRules(complexProperties, processedRoles);
	
		return complexProperties;
	}
	
	protected void collectLocalRules(Map<String, Property> complexProperties, Map<String, Set<Role>> processedRoles) {
		
		properties.forEach((propertyName, property)-> {
			
			Property complexProperty = complexProperties.get(propertyName);
			
			if(complexProperty == null) {
			
				complexProperty = new PropertyImpl(property.getOwner(), propertyName);
				complexProperties.put(propertyName, complexProperty);
			}
			
			if(!complexProperty.hasDefaultRule() && property.hasDefaultRule()) {
				
				complexProperty.setDefaultRule(property.getDefaultRule());
			}
			
			Set<Role> processedPropertyRoles = processedRoles.get(propertyName);

			if(processedPropertyRoles == null) {
				
				processedPropertyRoles = new HashSet<>();
				processedRoles.put(propertyName, processedPropertyRoles);
			}
			
			for(AccessRule localRule : property.getRules()) {
					
				if(processedPropertyRoles.containsAll(localRule.getRoles())) continue;
				
				processedPropertyRoles.addAll(localRule.getRoles());
				complexProperty.addRule(localRule);
			}
		});
	}
	
	protected void collectFromInterfaces(Map<String, Property> complexProperties, Map<String, Set<Role>> processedRoles) {
	
		Class<?>[] interfaces = type.getInterfaces();
		
		for(Class<?> interfaze : interfaces) {
			
			ProtectedType interfazeType = manager.getType(interfaze);
		
			if(interfazeType != null) {
				
				interfazeType.collectRules(complexProperties, processedRoles);
			}
		}
	}
	
	@Override
	public Property createProperty(String name) {
		
		Property prop = new PropertyImpl(this, name);
		
		properties.put(name, prop);
		
		return prop;
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
	public void setDefaultRule(AccessRule defaulRule) {
	
		this.defaultRule = defaulRule;
	}

	@Override
	public boolean hasDefaultRule() {
	
		return this.defaultRule != null;
	}

	@Override
	public AccessRule getDefaultRule() {
		
		return this.defaultRule;
	}

	@Override
	public Class<?> getTypeClass() {
		
		return this.type;
	}
}
