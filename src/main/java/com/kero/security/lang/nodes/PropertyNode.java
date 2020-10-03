package com.kero.security.lang.nodes;

import java.util.List;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.scheme.AccessScheme;

public class PropertyNode extends KsdlNodeBase {

	private String name;
	private DefaultRuleNode defaultRule;
	
	private GrantAccessRuleNode grantRule;
	private DenyAccessRuleNode denyRule;
	
	private List<PropertyMetalineBase> metalines;
	
	public PropertyNode(String name, DefaultRuleNode defaultRule, GrantAccessRuleNode grantRule, DenyAccessRuleNode denyRule, List<PropertyMetalineBase> metalines) {
		
		this.name = name;
		this.defaultRule = defaultRule;
		
		this.grantRule = grantRule;
		this.denyRule = denyRule;
		this.metalines = metalines;
	}

	public void interpret(AccessScheme scheme) {

		KeroAccessAgent manager = scheme.getAgent();
		
		Property prop = scheme.getOrCreateLocalProperty(name);

		defaultRule.interpret(manager, prop);
		
		grantRule.interpret(manager, prop);
		denyRule.interpret(manager, prop);
		
		for(PropertyMetalineBase metaline : metalines) {
			
			metaline.interpret(manager, prop);
		}
	}
}
