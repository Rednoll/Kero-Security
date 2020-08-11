package com.kero.security.core.property;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.type.ProtectedType;

public class PropertyImpl implements Property {

	private String name;
	
	private List<AccessRule> rules = new LinkedList<>();
	
	private AccessRule defaultRule;
	
	private ProtectedType owner;
	
	public PropertyImpl(ProtectedType owner, String name) {
		
		this.owner = owner;
		this.name = name;
	}
	
	public void addRule(AccessRule rule) {
		
		rules.add(rule);
	}
	
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
	public ProtectedType getOwner() {
		
		return this.owner;
	}
}
