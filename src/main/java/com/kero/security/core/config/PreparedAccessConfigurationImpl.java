package com.kero.security.core.config;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class PreparedAccessConfigurationImpl implements PreparedAccessConfiguration {

	private Map<String, PreparedRule> rules = new HashMap<>();
	
	public PreparedAccessConfigurationImpl() {}
	
	public PreparedAccessConfigurationImpl(Map<String, PreparedRule> rules) {
		
		this.rules = rules;
	}
	
	public Object process(Object original, Method method, Object[] args) {
		
		String name = method.getName();
		
		if(name.startsWith("get")) {
			
			name = name.replaceFirst("get", "");
			name = name.toLowerCase();
		}
		
		PreparedRule rule = rules.get(name);
		
		return rule.process(method, original, args);
	}
}
