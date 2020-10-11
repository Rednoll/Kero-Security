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

import com.kero.security.core.access.annotations.Access;
import com.kero.security.core.config.action.Action;
import com.kero.security.core.config.action.ActionDeny;
import com.kero.security.core.config.action.ActionGrant;
import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class LocalProperty implements Property {

	private String name;
	
	private AccessScheme scheme;
	
	private Access defaultAccess = Access.UNKNOWN;
	
	private Set<Role> grantRoles = new HashSet<>();
	private Set<Role> denyRoles = new HashSet<>();
	
	private DenyInterceptor defaultInterceptor;
	private List<DenyInterceptor> interceptors = new LinkedList<>();
	
	private Map<Role, Role> rolesPropagations = new HashMap<>();
	
	public LocalProperty(AccessScheme scheme, String name) {
		
		this.scheme = scheme;
		this.name = name;
	}
	
	public Access accessible(Collection<Role> rolesArg) {
		
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
	
	public Action prepare(Collection<Role> roles) {
		
		Access accessible = accessible(roles);
		
		if(accessible == Access.UNKNOWN) {
			
			accessible = determineDefaultAccess();
		}
		
		if(accessible == Access.GRANT) {
			
			return new ActionGrant(this.scheme, propagateRoles(roles));
		}
		else if(accessible == Access.DENY) {
		
			DenyInterceptor interceptor = determineInterceptor(roles);
			
			if(interceptor != null) {
				
				return interceptor.prepare(roles);
			}
			else {
				
				return new ActionDeny(this.scheme);
			}
		}
		else {
		
			throw new RuntimeException("Can't prepare property: "+this+", cause access "+accessible+". Your Kero-Security configuration is bad, if you see this exception.");
		}
	}
	
	protected Access determineDefaultAccess() {
		
		Access defaultAccess = getDefaultAccess();
	
		if(defaultAccess == Access.UNKNOWN) {
			
			defaultAccess = this.scheme.determineDefaultAccess();
		}
		
		return defaultAccess;
	}
	
	public DenyInterceptor determineInterceptor(Collection<Role> roles) {
		
		int maxOverlap = 0;
		int minTrash = Integer.MAX_VALUE;
		DenyInterceptor result = null;
		
		List<DenyInterceptor> interceptors = collectInterceptors();
		
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

			return getDefaultInterceptor();
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
	
		return this.collectInterceptors();
	}
	
	protected List<DenyInterceptor> collectInterceptors() {
		
		List<DenyInterceptor> interceptors = new ArrayList<>(this.interceptors);
		
		if(this.scheme.isInherit()) {
			
			interceptors.addAll(this.getParent().getInterceptors());
		}
		
		return interceptors;
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
		
		return this.defaultAccess != Access.UNKNOWN;
	}
	
	public Access getDefaultAccess() {
		
		return this.findDefaultAccess();
	}

	protected Access findDefaultAccess() {
		
		if(hasDefaultAccess()) return this.defaultAccess;

		if(!this.scheme.isInherit()) return Access.UNKNOWN;
		
		return getParent().getDefaultAccess();
	}
	
	public String getName() {
		
		return this.name;
	}

	public void setDefaultInterceptor(DenyInterceptor interceptor) {
		
		this.defaultInterceptor = interceptor;
	}

	public boolean hasDefaultInterceptor() {
		
		return this.defaultInterceptor != null;
	}

	public DenyInterceptor getDefaultInterceptor() {
		
		return this.findDefaultInterceptor();
	}

	protected DenyInterceptor findDefaultInterceptor() {
		
		if(hasDefaultInterceptor()) return this.defaultInterceptor;
		
		if(!this.scheme.isInherit()) return null;
		
		return this.getParent().getDefaultInterceptor();
	}
	
	public Property getParent() {
		
		return this.scheme.getParentProperty(this.name);
	}
}
