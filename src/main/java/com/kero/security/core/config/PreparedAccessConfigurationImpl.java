package com.kero.security.core.config;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import com.kero.security.core.config.action.Action;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.AccessScheme;

public class PreparedAccessConfigurationImpl implements PreparedAccessConfiguration {

	private Map<String, Action> actions = new HashMap<>();
	private Action defaultAction = null;
	private AccessScheme type = null;
	
	public PreparedAccessConfigurationImpl() {}
	
	public PreparedAccessConfigurationImpl(AccessScheme type, Map<String, Action> actions, Action defaultTypeAction) {
		
		this.type = type;
		this.actions = actions;
		this.defaultAction = defaultTypeAction;
	}
	
	@Override
	public Object invoke(Object proxy, Method method, Object[] args) {
		
		Object original = ((AccessProxy) proxy).getOriginal();
		
		String name = type.getAgent().extractPropertyName(method.getName());
		
		Action action = actions.get(name);
		
		if(action != null) {
			
			return action.process(method, original, args);
		}
		else {
			
			return defaultAction.process(method, original, args);
		}
	}
}
