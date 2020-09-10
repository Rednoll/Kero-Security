package com.kero.security.core;

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

public interface KeroAccessManager {
	
	//Roles
	public Role createRole(String name);
	public Role getRole(String name);
	public Role hasRole(String name);
	public Role getOrCreateRole(String name);
	public Set<Role> getOrCreateRole(Collection<String> names);
	public Set<Role> getOrCreateRole(String[] names);
	
	//AccessScheme
	public AccessScheme getOrCreateScheme(Class<?> rawType);
	public boolean hasScheme(Class<?> rawType);
	public AccessScheme getSchemeByAlise(String aliase);
	public AccessScheme getScheme(Class<?> rawType);

	//protect
	public default <T> T protect(T object, String... roleNames) {
		
		Set<Role> roles = this.getOrCreateRole(roleNames);
		
		return protect(object, roles);
	}
	
	public default <T> T protect(T object, Role... roles) {
		
		return protect(object, new HashSet<>(Arrays.asList(roles)));
	}
	
	public <T> T protect(T object, Collection<Role> roles);
	
	//uniq
	public void ignoreType(Class<?> type);

	public void addConfigurator(AccessSchemeAutoConfigurator configurator);
	
	public ClassLoader getClassLoader();
	
	public void setBasePackage(String basePackage);
	
	public void setTypeAliase(String aliase, Class<?> type);

	public AccessRule getDefaultRule();
	
	public String extractName(String rawName);

	//Delegates
	public RoleStorage getRoleStorage();
	public KeroAccessConfigurator getConfigurator();
}
