package com.kero.security.core.role.storage;

import java.util.HashMap;

import com.kero.security.core.role.Role;
import com.kero.security.core.role.RoleImpl;

public class RoleStorageImpl extends HashMap<String, Role> implements RoleStorage {

	@Override
	public Role create(String name) {
		
		Role role = new RoleImpl(name);
		
		this.put(name, role);
		
		return role;
	}
	
	public boolean has(String name) {
		
		return this.containsKey(name);
	}
}
