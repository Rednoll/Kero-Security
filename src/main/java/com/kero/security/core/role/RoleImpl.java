package com.kero.security.core.role;

public class RoleImpl implements Role {

	private String name;
	private int priority;
	
	public RoleImpl(String name, int priority) {
	
		this.name = name;
		this.priority = priority;
	}
	
	@Override
	public String getName() {
		
		return this.name;
	}

	@Override
	public int getPriority() {
		
		return this.priority;
	}
}
