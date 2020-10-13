package com.kero.security.core.property;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.kero.security.core.DefaultAccessOwner;
import com.kero.security.core.access.Access;
import com.kero.security.core.config.action.Action;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;

public interface Property extends DefaultAccessOwner {
	
	public static final Property EMPTY = new Empty();
	
	public Action prepare(Collection<Role> roles);

	public Access accessible(Collection<Role> rolesArg);

	public Role propagateRole(Role role);
	public Set<Role> propagateRoles(Collection<Role> roles);
	public boolean hasPropagationFor(Role target);
	public void addRolePropagation(Role from, Role to);

	public void grantRoles(Collection<Role> roles);
	public void grantRole(Role role);
	public Set<Role> getGrantRoles();

	public void denyRoles(Collection<Role> roles);
	public void denyRole(Role role);
	public Set<Role> getDenyRoles();
	
	public DenyInterceptor determineInterceptor(Collection<Role> roles);
	public void addInterceptor(DenyInterceptor interceptor);
	public List<DenyInterceptor> getInterceptors();
	
	public void setDefaultInterceptor(DenyInterceptor interceptor);
	public boolean hasDefaultInterceptor();
	public DenyInterceptor getDefaultInterceptor();
	
	public String getName();
	
	public Property getParent();
	
	public static class Empty implements Property {

		private Empty() {}
		
		@Override
		public Access accessible(Collection<Role> rolesArg) {
			
			return Access.UNKNOWN;
		}
		
		@Override
		public void setDefaultAccess(Access access) {}

		@Override
		public boolean hasDefaultAccess() {
			
			return false;
		}

		@Override
		public Access getDefaultAccess() {
			
			return Access.UNKNOWN;
		}

		@Override
		public void addRolePropagation(Role from, Role to) {}

		@Override
		public Set<Role> propagateRoles(Collection<Role> roles) {
			
			return new HashSet<>(roles);
		}
		
		@Override
		public void grantRole(Role role) {}

		@Override
		public void grantRoles(Collection<Role> roles) {}
		
		@Override
		public Set<Role> getGrantRoles() {
			
			return Collections.emptySet();
		}

		@Override
		public void denyRole(Role rule) {}

		@Override
		public void denyRoles(Collection<Role> roles) {}
		
		@Override
		public Set<Role> getDenyRoles() {
			
			return Collections.emptySet();
		}

		@Override
		public void setDefaultInterceptor(DenyInterceptor interceptor) {}

		@Override
		public boolean hasDefaultInterceptor() {
			
			return false;
		}

		@Override
		public DenyInterceptor getDefaultInterceptor() {
			
			return null;
		}

		@Override
		public void addInterceptor(DenyInterceptor interceptor) {}

		@Override
		public List<DenyInterceptor> getInterceptors() {
			
			return Collections.emptyList();
		}

		@Override
		public String getName() {
			
			return null;
		}

		@Override
		public boolean hasPropagationFor(Role role) {
			
			return false;
		}

		@Override
		public Role propagateRole(Role role) {
			
			return role;
		}

		@Override
		public Action prepare(Collection<Role> roles) {

			return Action.EMPTY;
		}
		
		@Override
		public Property getParent() {
			
			return this;
		}

		@Override
		public DenyInterceptor determineInterceptor(Collection<Role> roles) {
		
			return null;
		}
	}
}