package com.kero.security.core.config;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class PreparedAccessConfigurationImpl implements PreparedAccessConfiguration {

	private Map<String, PreparedAction> actions = new HashMap<>();
	private PreparedAction defaultAction = null;
	
	public PreparedAccessConfigurationImpl() {}
	
	public PreparedAccessConfigurationImpl(Map<String, PreparedAction> actions, PreparedAction defaultTypeAction) {
		
		this.actions = actions;
		this.defaultAction = defaultTypeAction;
	}
	
	public Object process(Object original, Method method, Object[] args) {
		
		String name = method.getName();
		
		if(name.startsWith("get")) {
			
			name = name.replaceFirst("get", "");
			name = name.toLowerCase();
		}
		
		PreparedAction action = actions.get(name);
		
		if(action != null) {
			
			return action.process(method, original, args);
		}
		else {
			
			return defaultAction.process(method, original, args);
		}
	}
}
