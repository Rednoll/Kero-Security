package com.kero.security.core.scheme;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.access.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.Role;

public class AccessSchemeCacheWrap implements AccessScheme {

	protected AccessScheme original;
	
	protected Map<Collection<Role>, PreparedAccessConfiguration> configsCache = new HashMap<>();
	
	public AccessSchemeCacheWrap(AccessScheme original) {
		
		this.original = original;
	}

	@Override
	public PreparedAccessConfiguration prepareAccessConfiguration(Collection<Role> roles) {
		
		roles = Collections.unmodifiableSet(new HashSet<>(roles));

		return configsCache.computeIfAbsent(roles, original::prepareAccessConfiguration);
	}
	
	@Override
	public void setDefaultAccess(Access access) {
		
		original.setDefaultAccess(access);;
	}

	@Override
	public boolean hasDefaultAccess() {
		
		return original.hasDefaultAccess();
	}

	@Override
	public Access getDefaultAccess() {
	
		return original.getDefaultAccess();
	}

	@Override
	public void setInherit(boolean i) {
		
		original.setInherit(i);
	}

	@Override
	public boolean isInherit() {
		
		return original.isInherit();
	}

	@Override
	public Property createLocalProperty(String name) {
		
		return original.createLocalProperty(name);
	}

	@Override
	public boolean hasLocalProperty(String name) {
		
		return original.hasLocalProperty(name);
	}

	@Override
	public Property getLocalProperty(String name) {
		
		return original.getLocalProperty(name);
	}

	@Override
	public Set<Property> getLocalProperties() {
		
		return original.getLocalProperties();
	}

	@Override
	public Class<?> getTypeClass() {
		
		return original.getTypeClass();
	}

	@Override
	public String getName() {
		
		return original.getName();
	}

	@Override
	public KeroAccessAgent getAgent() {
		
		return original.getAgent();
	}

	@Override
	public Set<Property> collectProperties() {
		
		return original.collectProperties();
	}

	@Override
	public Access determineDefaultAccess() {
		
		return original.determineDefaultAccess();
	}
}
