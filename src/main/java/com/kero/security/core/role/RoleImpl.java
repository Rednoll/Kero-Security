package com.kero.security.core.role;

import java.util.Objects;

public class RoleImpl implements Role, Comparable<RoleImpl> {

	private String name;
	private int priority;
	
	public RoleImpl(String name, int priority) {
	
		this.name = name;
		this.priority = priority;
	}
	
	@Override
	public int hashCode() {
		return Objects.hash(name, priority);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RoleImpl other = (RoleImpl) obj;
		return Objects.equals(name, other.name) && priority == other.priority;
	}

	@Override
	public String getName() {
		
		return this.name;
	}

	@Override
	public int getPriority() {
		
		return this.priority;
	}

	@Override
	public int compareTo(RoleImpl another) {
		
		return another.priority - this.priority;
	}
}
