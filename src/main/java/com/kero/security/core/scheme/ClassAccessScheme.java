package com.kero.security.core.scheme;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.access.annotations.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.config.PreparedAccessConfigurationImpl;
import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.property.LocalProperty;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;

public class ClassAccessScheme implements AccessScheme {

	protected static Logger LOGGER = LoggerFactory.getLogger("Kero-Security");
	
	protected Class<?> type;
	protected String name;
	
	protected Access defaultAccess = Access.UNKNOWN;
	
	protected Map<String, Property> localProperties = new HashMap<>();
	
	protected KeroAccessAgent agent;
	
	protected boolean inherit = true;
	
	public ClassAccessScheme() {
	
	}
	
	public ClassAccessScheme(KeroAccessAgent agent, String name, Class<?> type) {

		this.agent = agent;
		this.name = name;
		this.type = type;
	}

	public PreparedAccessConfiguration prepareAccessConfiguration(Collection<Role> rolesArg) {
		
		Set<Role> roles = new HashSet<>(rolesArg);
		
		String rolesList = "[";
		
		for(Role role : roles) {
			
			rolesList += role.getName()+" ";
		}
		
		rolesList = rolesList.trim()+"]";
		
		LOGGER.debug("Prepare access configuration for "+type.getCanonicalName()+" roles: "+rolesList);
		
		Map<String, PreparedAction> preparedActions = new HashMap<>();

		Set<Property> properties = collectProperties();
		
			properties.forEach((property)-> {
	
				preparedActions.put(property.getName(), property.prepare(roles));
			});

		PreparedAction defaultAction = determineDefaultAction(roles);
		
		return new PreparedAccessConfigurationImpl(this, preparedActions, defaultAction);
	}
	
	protected PreparedAction determineDefaultAction(Collection<Role> roles) {
		
		Access defaultAccess = determineDefaultAccess();
	
		if(defaultAccess == Access.GRANT) {
			
			return new PreparedGrantRule(this, roles);
		}
		else if(defaultAccess == Access.DENY) {
			
			return new PreparedDenyRule(this);
		}
		
		throw new RuntimeException("Can't prepare default access for : "+this+". Your Kero-Security configuration is bad, if you see this exception.");
	}
	
	public Set<Property> collectProperties() {
	
		Map<String, Property> props = new HashMap<>();
		
		for(Property prop : getLocalProperties()) {
			
			props.put(prop.getName(), prop);
		}
		
		if(this.isInherit()) {
			
			Set<Property> parentProps = this.getParent().collectProperties();
			
			parentProps.forEach(prop -> props.putIfAbsent(prop.getName(), prop));
		}
		
		return new HashSet<>(props.values());
	}
	
	public Access determineDefaultAccess() {
		
		Access access = findDefaultAccess();
		
		if(access == Access.UNKNOWN) {
			
			access = agent.getDefaultAccess();
		}
		
		return access;
	}
	
	protected Access findDefaultAccess() {
		
		if(this.hasDefaultAccess()) return this.getDefaultAccess();
		
		if(!this.inherit) return Access.UNKNOWN;
		
		return getParent().determineDefaultAccess();
	}

	@Override
	public Property createLocalProperty(String name) {
		
		LOGGER.debug("Creating property: "+name+" for scheme: "+this.getTypeClass().getSimpleName());
		
		Property prop = new LocalProperty(this, name);
		
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
	public void setDefaultAccess(Access access) {
	
		this.defaultAccess = access;
	}

	@Override
	public boolean hasDefaultAccess() {
	
		return this.defaultAccess != Access.UNKNOWN;
	}

	@Override
	public Access getDefaultAccess() {
		
		return this.defaultAccess;
	}

	@Override
	public Class<?> getTypeClass() {
		
		return this.type;
	}
	
	@Override
	public KeroAccessAgent getAgent() {
		
		return this.agent;
	}
	
	@Override
	public String getName() {
		
		return this.name;
	}
	
	@Override
	public void setInherit(boolean i) {
		
		this.inherit = i;
	}
	
	@Override
	public boolean isInherit() {
		
		return this.inherit;
	}
}
