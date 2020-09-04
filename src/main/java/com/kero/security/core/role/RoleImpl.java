package com.kero.security.core.role;

import java.util.Objects;

public class RoleImpl implements Role, Comparable<RoleImpl> {

	private String name;
	
	public RoleImpl(String name) {
	
		this.name = name;
	}
	
	@Override
	public String toString() {
		
		return name;
	}

	@Override
	public int hashCode() {
		return Objects.hash(name);
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
		return Objects.equals(name, other.name);
	}

	@Override
	public String getName() {
		
		return this.name;
	}
	
	@Override
	public int compareTo(RoleImpl another) {
		
		return this.name.compareTo(another.name);
	}
}
