package com.kero.security.core.config;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import com.kero.security.core.config.prepared.PreparedAction;
import com.kero.security.core.scheme.AccessScheme;

public class PreparedAccessConfigurationImpl implements PreparedAccessConfiguration {

	private Map<String, PreparedAction> actions = new HashMap<>();
	private PreparedAction defaultAction = null;
	private AccessScheme type = null;
	
	public PreparedAccessConfigurationImpl() {}
	
	public PreparedAccessConfigurationImpl(AccessScheme type, Map<String, PreparedAction> actions, PreparedAction defaultTypeAction) {
		
		this.type = type;
		this.actions = actions;
		this.defaultAction = defaultTypeAction;
	}
	
	public Object process(Object original, Method method, Object[] args) {
		
		String name = type.getManager().extractName(method.getName());
		
		PreparedAction action = actions.get(name);
		
		if(action != null) {
			
			return action.process(method, original, args);
		}
		else {
			
			return defaultAction.process(method, original, args);
		}
	}
}
