package com.kero.security.core.lang.nodes;

import java.util.Set;

import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.AccessScheme;

public class TypeNode extends KsdlNodeBase {

	private Class<?> type;
	private AccessRule defaultRule;
	private Set<PropertyNode> properties;
	
	public TypeNode(Class<?> type, AccessRule defaultRule, Set<PropertyNode> properties) {
		
		this.type = type;
		this.defaultRule = defaultRule;
		this.properties = properties;
	}
	
	public void interpret(KeroAccessManager manager) {
		
		AccessScheme scheme = manager.getOrCreateScheme(type);
	
		if(defaultRule != null) {
			
			scheme.setDefaultRule(defaultRule);
		}
		
		properties.forEach((prop)-> prop.interpret(scheme));
	}
}