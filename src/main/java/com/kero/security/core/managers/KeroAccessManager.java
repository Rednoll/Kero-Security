package com.kero.security.core.managers;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;
import com.kero.security.core.type.ProtectedType;

public interface KeroAccessManager {
	

	public Role createRole(String name, int priority);
	public Role getRole(String name);
	public Role getOrCreateRole(String name);
	
	public ProtectedType getOrCreateType(Class<?> rawType);
	
	public boolean hasType(Class<?> rawType);
	public ProtectedType getType(Class<?> rawType);
	public ObjectTypeAccessManager type(Class<?> rawType);
	
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
}
