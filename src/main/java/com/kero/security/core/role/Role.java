package com.kero.security.core.role;

import java.util.HashMap;
import java.util.Map;

public interface Role {

	Map<String, Role> registry = new HashMap<>();
	
	public String getName();
	public int getPriority();
	
	public static Role get(String name) {
		
		return registry.get(name);
	}
	
	public static Role getOrCreate(String name) {
		
		if(get(name) != null) {
			
			return get(name);
		}
		else {
			
			return create(name, 1);
		}
	}
	
	public static Role create(String name, int priority) {
		
		Role role = new RoleImpl(name, priority);
			
		registry.put(name, role);
		
		return role;
	}
}
