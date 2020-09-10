package com.kero.security.core.role.storage;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.role.Role;

public interface RoleStorage extends Map<String, Role> {
	
	public Role create(String name);
	public boolean has(String name);
	
	public default Role getOrCreate(String name) {
		
		return has(name) ? get(name) : create(name);
	}
	
	public default Set<Role> getOrCreate(String[] names) {
		
		return getOrCreate(Arrays.asList(names));
	}

	public default Set<Role> getOrCreate(Collection<String> names) {
		
		Set<Role> result = new HashSet<>();
		
		for(String name : names) {
			
			result.add(getOrCreate(name));
		}
		
		return result;
	}
	
	public static RoleStorage create() {
		
		return new RoleStorageImpl();
	}
}
