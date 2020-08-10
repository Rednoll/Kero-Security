package com.kero.security.core.property;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import com.kero.security.core.exception.AccessException;
import com.kero.security.core.role.Role;
import com.kero.security.core.rules.AccessRule;

public class PropertyImpl implements Property {

	private String name;
	
	private List<AccessRule> rules = new LinkedList<>();
	
	private AccessRule defaultRule = null;
	
	public PropertyImpl(String name, AccessRule defaultRule) {
		
		this.name = name;
		this.defaultRule = defaultRule;
	}
	
	public void addRule(AccessRule rule) {
		
		rules.add(0, rule);
	}
	
	@Override
	public Object tryInvoke(Object target, Method method, Object[] args, Set<Role> roles) throws Exception {
		
		List<AccessRule> suitableRules = collectRules(roles);	
		Set<Role> processedRoles = new HashSet<>();
		
		for(AccessRule rule : suitableRules) {
		
			if(rule.accessible(roles)) {
				
				return method.invoke(target, args);
			}
			
			processedRoles.addAll(rule.getRoles());
		}
		
		suitableRules.sort((a, b)-> a.getHighestPriorityRole().getPriority() - b.getHighestPriorityRole().getPriority());
		
		for(AccessRule rule : suitableRules) {
		
			if(rule.hasSilentInterceptor()) {
				
				return rule.processSilentInterceptor(target);
			}
		}
		
		if(processedRoles.containsAll(roles)) {
			
			throw new AccessException("Access denied for "+method.getName()); //TODO: verbose exception
		}
		
		if(defaultRule.accessible(roles)) {
			
			return method.invoke(target, args);
		}
		
		if(defaultRule.hasSilentInterceptor()) {
			
			return defaultRule.processSilentInterceptor(target);
		}

		throw new AccessException("Access denied for "+method.getName()); //TODO: verbose exception
	}
	
	private List<AccessRule> collectRules(Set<Role> roles) {
		
		List<AccessRule> collected = new LinkedList<>();
		
		for(AccessRule suspectRule : this.rules) {
			
			if(suspectRule.manage(roles)) {
				
				collected.add(suspectRule);
			}
		}
		
		return collected;
	}
	
	@Override
	public void setDefaultRule(AccessRule rule) {
		
		this.defaultRule = rule;
	}
	
	@Override
	public String getName() {
		
		return this.name;
	}
}
