package com.kero.security.core.property;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.core.interceptor.FailureInterceptor;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.type.ProtectedType;

public class PropertyImpl implements Property {

	private String name;
	
	private List<AccessRule> rules = new LinkedList<>();
	
	private List<FailureInterceptor> interceptors = new LinkedList<>();
	
	private AccessRule defaultRule;
	
	private FailureInterceptor defaultInterceptor;
	
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
	}
	
	public void addInterceptor(FailureInterceptor interceptor) {
		
		this.interceptors.add(interceptor);
	}
	
	public List<FailureInterceptor> getInterceptors() {
	
		return this.interceptors;
	}
	
	public void addRule(AccessRule rule) {
		
		this.rules.add(rule);
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
	public void setDefaultInterceptor(FailureInterceptor interceptor) {
		
		this.defaultInterceptor = interceptor;
	}

	@Override
	public boolean hasDefaultInterceptor() {
		
		return getDefaultInterceptor() != null;
	}

	@Override
	public FailureInterceptor getDefaultInterceptor() {
		
		return this.defaultInterceptor;
	}
}
