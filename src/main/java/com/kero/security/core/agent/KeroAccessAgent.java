package com.kero.security.core.agent;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.storage.RoleStorage;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configuration.KeroAccessConfigurator;
import com.kero.security.core.scheme.configuration.auto.AccessSchemeAutoConfigurator;
import com.kero.security.core.scheme.storage.AccessSchemeStorage;

public interface KeroAccessAgent {
	
	public void ignoreType(Class<?> type);

	public void addConfigurator(AccessSchemeAutoConfigurator configurator);
	
	public ClassLoader getClassLoader();
	
	public void setTypeAliase(String aliase, Class<?> type);

	public AccessRule getDefaultRule();
	
	public String extractName(String rawName);

	public Role createRole(String name);
	public Role getRole(String name);
	public Role hasRole(String name);
	public Role getOrCreateRole(String name);
	public Set<Role> getOrCreateRole(Collection<String> names);
	public Set<Role> getOrCreateRole(String[] names);
	
	public AccessScheme getOrCreateScheme(Class<?> rawType);
	public boolean hasScheme(Class<?> rawType);
	public AccessScheme getSchemeByAlise(String aliase);
	public AccessScheme getScheme(Class<?> rawType);

	public default <T> T protect(T object, String... roleNames) {
		
		Set<Role> roles = this.getOrCreateRole(roleNames);
		
		return protect(object, roles);
	}
	
	public default <T> T protect(T object, Role... roles) {
		
		return protect(object, new HashSet<>(Arrays.asList(roles)));
	}
	
	public <T> T protect(T object, Collection<Role> roles);

	public AccessSchemeStorage getSchemeStorage();
	public RoleStorage getRoleStorage();
	public KeroAccessConfigurator getConfigurator();
}
