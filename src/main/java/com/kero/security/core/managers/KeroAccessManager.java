package com.kero.security.core.managers;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.AccessScheme;

public interface KeroAccessManager {
	
	public void ignoreType(Class<?> type);
	
	public Role createRole(String name);
	public Role getRole(String name);
	public Role getOrCreateRole(String name);
	
	public AccessScheme getOrCreateScheme(Class<?> rawType);
	
	public boolean hasScheme(Class<?> rawType);
	public AccessScheme getScheme(Class<?> rawType);
	public AccessSchemeManager scheme(Class<?> rawType);
	
	public ClassLoader getClassLoader();
	
	public default <T> T protect(T object, String... roleNames) {
		
		Set<Role> roles = new HashSet<>();
		
		for(String name : roleNames) {
			
			roles.add(this.getOrCreateRole(name));
		}
		
		return protect(object, roles);
	}
	
	public default <T> T protect(T object, Role... roles) {
		
		return protect(object, new HashSet<>(Arrays.asList(roles)));
	}
	
	public <T> T protect(T object, Set<Role> roles);
	
	public AccessRule getDefaultRule();
	
	public String extractName(String rawName);
}
