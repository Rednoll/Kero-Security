package com.kero.security.core.role.storage;

import java.util.HashMap;
import java.util.Map;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;

public class RoleStorageImpl implements RoleStorage {

	protected Map<String, Role> roles = new HashMap<>();
	
	@Override
	public Role create(String name) {
		
		Role role = new RoleImpl(name);
		
		roles.put(name, role);
		
		return role;
	}
	
	public Role get(String name) {
		
		return roles.get(name);
	}
	
	public boolean has(String name) {
		
		return this.roles.containsKey(name);
	}
}
