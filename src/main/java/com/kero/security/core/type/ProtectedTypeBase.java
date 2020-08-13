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
	
	protected AccessRule defaultRule;
	
	protected Map<String, Property> localProperties = new HashMap<>();
	
	protected KeroAccessManager manager;
	
	protected boolean inherit = true;

	public ProtectedTypeBase() {
		
	}
	
	public ProtectedTypeBase(KeroAccessManager manager, Class<?> type) {
		
		this.manager = manager;
		this.type = type;
	}

	public Set<Property> getProperties() {
	
		Map<String, Property> complexProperties = new HashMap<>();

		collectProperties(complexProperties);
	
		return new HashSet<>(complexProperties.values());
	}
	
	protected void collectLocalProperties(Map<String, Property> complexProperties) {
		
		localProperties.forEach((propertyName, property)-> {
			
			Property complexProperty = complexProperties.get(propertyName);
			
			if(complexProperty == null) {
			
				complexProperty = new PropertyImpl(propertyName);
				complexProperties.put(propertyName, complexProperty);
			}
			
			complexProperty.inherit(property);
		});
	}
	
	protected void collectFromInterfaces(Map<String, Property> complexProperties) {
	
		Class<?>[] interfaces = type.getInterfaces();
		
		for(Class<?> interfaze : interfaces) {
			
			ProtectedType interfazeType = manager.getType(interfaze);
		
			if(interfazeType != null) {
				
				interfazeType.collectProperties(complexProperties);
			}
		}
	}
	
	@Override
	public void setInherit(boolean i) {
		
		this.inherit = i;
	}
	
	@Override
	public boolean isInherit() {
		
		return this.inherit;
	}
	
	@Override
	public Property createLocalProperty(String name) {
		
		Property prop = new PropertyImpl(name);
		
		localProperties.put(name, prop);
		
		return prop;
	}

	@Override
	public boolean hasLocalProperty(String name) {
		
		return localProperties.containsKey(name);
	}

	@Override
	public Property getLocalProperty(String name) {
		
		return localProperties.get(name);
	}

	@Override
	public Set<Property> getLocalProperties() {
		
		return new HashSet<>(localProperties.values());
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
