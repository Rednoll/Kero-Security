package com.kero.security.core.lang.nodes;

import com.kero.security.core.property.Property;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.AccessScheme;

public class PropertyNode extends KsdlNodeBase {

	private String name;
	private AccessRule defaultRule;
	
	private AccessRule grantRule;
	private AccessRule denyRule;
	
	public PropertyNode(String name, AccessRule defaultRule, AccessRule grantRule, AccessRule denyRule) {
		
		this.name = name;
		this.defaultRule = defaultRule;
		
		this.grantRule = grantRule;
		this.denyRule = denyRule;
	}

	public void interpret(AccessScheme scheme) {
		
		Property prop = scheme.getOrCreateLocalProperty(name);
		
		if(defaultRule != null) {
			
			prop.setDefaultRule(defaultRule);
		}
		
		prop.addRule(grantRule);
		prop.addRule(denyRule);
	}
}
