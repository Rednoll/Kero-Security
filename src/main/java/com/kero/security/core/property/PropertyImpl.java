package com.kero.security.core.property;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.kero.security.core.interceptor.DenyInterceptor;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public class PropertyImpl implements Property {

	private String name;
	
	private AccessRule defaultRule;
	private List<AccessRule> rules = new LinkedList<>();

	private DenyInterceptor defaultInterceptor;
	private List<DenyInterceptor> interceptors = new LinkedList<>();
	
	private Map<Role, Role> rolesPropagations = new HashMap<>();
	
	public PropertyImpl(String name) {
		
		this.name = name;
	}
	
	@Override
	public void inherit(Property parent) {
		
		if(!this.hasDefaultRule() && parent.hasDefaultRule()) {
			
			this.setDefaultRule(parent.getDefaultRule());
		}
		
		this.rules.addAll(parent.getRules());
		
		if(!this.hasDefaultInterceptor() && parent.hasDefaultInterceptor()) {
			
			this.setDefaultInterceptor(parent.getDefaultInterceptor());
		}
		
		this.interceptors.addAll(parent.getInterceptors());
		
		parent.getRolesPropagation().forEach((from, to)-> {
			
			if(!this.rolesPropagations.containsKey(from)) {
				
				this.addRolePropagation(from, to);
			}
		});
	}
	
	@Override
	public Set<Role> propagateRoles(Collection<Role> roles) {
		
		Set<Role> result = new HashSet<>();
		
		for(Role role : roles) {
		
			result.add(rolesPropagations.getOrDefault(role, role));
		}
		
		return result;
	}
	
	@Override
	public void addRolePropagation(Role from, Role to) {
		
		this.rolesPropagations.put(from, to);
	}
	
	@Override
	public void addInterceptor(DenyInterceptor interceptor) {
		
		this.interceptors.add(interceptor);
	}
	
	@Override
	public List<DenyInterceptor> getInterceptors() {
	
		return this.interceptors;
	}
	
	@Override
	public void addRule(AccessRule rule) {
		
		this.rules.add(rule);
	}
	
	@Override
	public List<AccessRule> getRules() {
		
		return this.rules;
	}

	@Override
	public void setDefaultRule(AccessRule rule) {
		
		this.defaultRule = rule;
	}

	@Override
	public boolean hasDefaultRule() {
		
		return getDefaultRule() != null;
	}
	
	@Override
	public AccessRule getDefaultRule() {
		
		return this.defaultRule;
	}
	
	@Override
	public String getName() {
		
		return this.name;
	}

	@Override
	public void setDefaultInterceptor(DenyInterceptor interceptor) {
		
		this.defaultInterceptor = interceptor;
	}

	@Override
	public boolean hasDefaultInterceptor() {
		
		return getDefaultInterceptor() != null;
	}

	@Override
	public DenyInterceptor getDefaultInterceptor() {
		
		return this.defaultInterceptor;
	}

	@Override
	public Map<Role, Role> getRolesPropagation() {
	
		return this.rolesPropagations;
	}
}
