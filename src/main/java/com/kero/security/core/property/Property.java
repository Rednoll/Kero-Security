package com.kero.security.core.property;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.DefaultAccessOwner;
import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.config.prepared.PreparedDenyRule;
import com.kero.security.core.config.prepared.PreparedGrantRule;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class Property implements DefaultAccessOwner {

	public static Property EMPTY = new Empty();
	
	private String name;
	
	private AccessScheme scheme;
	
	private Access defaultAccess = Access.UNKNOWN;
	
	private Set<Role> grantRoles = new HashSet<>();
	private Set<Role> denyRoles = new HashSet<>();
	
	private DenyInterceptor defaultInterceptor;
	private List<DenyInterceptor> interceptors = new LinkedList<>();
	
	private Map<Role, Role> rolesPropagations = new HashMap<>();
	
	public Property(AccessScheme scheme, String name) {
		
		this.scheme = scheme;
		this.name = name;
	}
	
	protected Access accessible(Collection<Role> rolesArg) {
		
		Set<Role> roles = new HashSet<>(rolesArg);
	
		if(roles.isEmpty()) {
			
			return Access.UNKNOWN;
		}
		
		roles.removeAll(this.denyRoles);
		
		if(roles.isEmpty()) {
			
			return Access.DENY;
		}
		
		if(!Collections.disjoint(roles, this.grantRoles)) {
			
			return Access.GRANT;
		}
		
		if(this.scheme.isInherit()) {
			
			return getParent().accessible(roles);
		}
		else {
			
			return Access.UNKNOWN;
		}
	}
	
	public PreparedAction prepare(Collection<Role> roles) {
		
		Access accessible = accessible(roles);
		
		if(accessible == Access.UNKNOWN) {
			
			accessible = determineDefaultAccess();
		}
		
		if(accessible == Access.GRANT) {
			
			return new PreparedGrantRule(this.scheme, propagateRoles(roles));
		}
		else if(accessible == Access.DENY) {
		
			DenyInterceptor interceptor = determineInterceptor(roles);
			
			if(interceptor != null) {
				
				return interceptor.prepare(roles);
			}
			else {
				
				return new PreparedDenyRule(this.scheme);
			}
		}
		else {
		
			throw new RuntimeException("Can't prepare property: "+this+", cause access "+accessible+". Your Kero-Security configuration is bad, if you see this exception.");
		}
	}
	
	private Access determineDefaultAccess() {
		
		if(hasDefaultAccess()) return getDefaultAccess();

		if(this.scheme.isInherit()) {
		
			Property parent = this.getParent();
			
			while(parent != Property.EMPTY) {
				
				if(parent.hasDefaultAccess()) {
					
					return parent.getDefaultAccess();
				}
				
				parent = parent.getParent();
			}
		}
		
		return scheme.determineDefaultAccess();
	}
	
	private DenyInterceptor determineInterceptor(Collection<Role> roles) {
		
		int maxOverlap = 0;
		int minTrash = Integer.MAX_VALUE;
		DenyInterceptor result = null;
		
		List<DenyInterceptor> interceptors = new ArrayList<>(this.interceptors);
		
		if(this.scheme.isInherit()) {
			
			Property parent = this.getParent();
			
			while(parent != Property.EMPTY) {
				
				interceptors.addAll(parent.getInterceptors());
				
				parent = parent.getParent();
			}
		}
		
		for(DenyInterceptor interceptor : interceptors) {
			
			Set<Role> interceptorRoles = interceptor.getRoles();
			
			int overlap = 0;
			int trash = 0;
			
			for(Role interceptorRole : interceptorRoles) {
				
				if(roles.contains(interceptorRole)) {
					
					overlap++;
				}
				else {
					
					trash++;
				}
			}
			
			if(overlap > maxOverlap) {
				
				maxOverlap = overlap;
				minTrash = trash;
				result = interceptor;
			}
			else if(overlap == maxOverlap && trash < minTrash) {
				
				maxOverlap = overlap;
				minTrash = trash;
				result = interceptor;
			}
		}
	
		if(maxOverlap == 0) {
			
			if(hasDefaultInterceptor()) {
				
				return getDefaultInterceptor();
			}
			
			if(this.scheme.isInherit()) {
				
				Property parent = this.getParent();
				
				while(parent != Property.EMPTY) {
					
					if(parent.hasDefaultInterceptor()) {
						
						return parent.getDefaultInterceptor();
					}
					
					parent = parent.getParent();
				}
			}
			
			return null;
		}
		
		return result;
	}
	
	public Role propagateRole(Role role) {
		
		Set<Role> data = new HashSet<>();
			data.add(role);
			
		return propagateRoles(data).iterator().next();
	}
	
	public Set<Role> propagateRoles(Collection<Role> roles) {
		
		Set<Role> result = new HashSet<>();
		Set<Role> propagated = new HashSet<>();

		for(Role fromRole : roles) {
			
			if(hasPropagationFor(fromRole)) {
				
				result.add(this.rolesPropagations.get(fromRole));
				propagated.add(fromRole);
			}
		}
		
		roles.removeAll(propagated);
		
		if(!roles.isEmpty()) {
			
			result.addAll(this.getParent().propagateRoles(roles));
		}
		
		return result;
	}
	
	public boolean hasPropagationFor(Role target) {
		
		return rolesPropagations.containsKey(target);
	}
	
	public void addRolePropagation(Role from, Role to) {
		
		this.rolesPropagations.put(from, to);
	}
	
	public void addInterceptor(DenyInterceptor interceptor) {
		
		this.interceptors.add(interceptor);
	}
	
	public List<DenyInterceptor> getInterceptors() {
	
		return this.interceptors;
	}
	
	public void grantRoles(Collection<Role> roles) {
		
		for(Role role : roles) {
			
			grantRole(role);
		}
	}
	
	public void grantRole(Role role) {
		
		if(this.denyRoles.contains(role)) throw new RuntimeException("Detected roles collision: "+role);
		
		this.grantRoles.add(role);
	}
	
	public void denyRoles(Collection<Role> roles) {
		
		for(Role role : roles) {
			
			denyRole(role);
		}
	}

	public void denyRole(Role role) {
		
		if(this.grantRoles.contains(role)) throw new RuntimeException("Detected roles collision: "+role);
		
		this.denyRoles.add(role);
	}

	public Set<Role> getGrantRoles() {
		
		return this.grantRoles;
	}
	
	public Set<Role> getDenyRoles() {
		
		return this.denyRoles;
	}

	public void setDefaultAccess(Access access) {
		
		this.defaultAccess = access;
	}

	public boolean hasDefaultAccess() {
		
		return getDefaultAccess() != Access.UNKNOWN;
	}
	
	public Access getDefaultAccess() {
		
		return this.defaultAccess;
	}
	
	public String getName() {
		
		return this.name;
	}

	public void setDefaultInterceptor(DenyInterceptor interceptor) {
		
		this.defaultInterceptor = interceptor;
	}

	public boolean hasDefaultInterceptor() {
		
		return getDefaultInterceptor() != null;
	}

	public DenyInterceptor getDefaultInterceptor() {
		
		return this.defaultInterceptor;
	}

	public Property getParent() {
		
		AccessScheme parentScheme = this.scheme.getParent();
		
		while(parentScheme != AccessScheme.EMPTY) {
			
			if(parentScheme.hasLocalProperty(this.name)) {
				
				return parentScheme.getLocalProperty(this.name);
			}
			
			parentScheme = parentScheme.getParent();
		}
	
		return Property.EMPTY;
	}
	
	private static class Empty extends Property {

		private Empty() {
			super(null, null);
		
		}
		
		@Override
		protected Access accessible(Collection<Role> rolesArg) {
			
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
		public void addRolePropagation(Role from, Role to) {
			
		}

		@Override
		public Set<Role> propagateRoles(Collection<Role> roles) {
			
			return new HashSet<>(roles);
		}

		@Override
		public void grantRole(Role role) {}

		@Override
		public Set<Role> getGrantRoles() {
			
			return Collections.EMPTY_SET;
		}

		@Override
		public void denyRole(Role rule) {}

		@Override
		public Set<Role> getDenyRoles() {
			
			return Collections.EMPTY_SET;
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
			
			return Collections.EMPTY_LIST;
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
		public PreparedAction prepare(Collection<Role> roles) {

			return null;
		}
		
		@Override
		public Property getParent() {
			
			return Property.EMPTY;
		}
	}
}