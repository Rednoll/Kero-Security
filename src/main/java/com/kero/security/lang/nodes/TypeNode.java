package com.kero.security.lang.nodes;

import java.util.Set;

import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.managers.KeroAccessManager;

public class TypeNode extends KsdlNodeBase implements KsdlRootNode {

	private String typeName;
	private Boolean defaultRule;
	private Set<PropertyNode> properties;
	
	public TypeNode(String typeName, Boolean defaultRule, Set<PropertyNode> properties) {
		
		this.typeName = typeName;
		this.defaultRule = defaultRule;
		this.properties = properties;
	}
	
	public void interpret(KeroAccessManager manager) {
		
		AccessScheme scheme = manager.getOrCreateScheme(manager.getTypeByAliase(typeName));
	
		if(defaultRule != null) {
			
			scheme.setDefaultRule(defaultRule ? AccessRule.GRANT_ALL : AccessRule.DENY_ALL);
		}
		
		properties.forEach((prop)-> prop.interpret(scheme));
	}
}