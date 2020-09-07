package com.kero.security.lang.nodes;

import java.util.List;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.scheme.AccessScheme;

public class SchemeNode extends KsdlNodeBase implements KsdlRootNode {

	private String typeName;
	
	private DefaultRuleNode defaultRule;
	
	private List<PropertyNode> properties;
	
	public SchemeNode(String typeName, DefaultRuleNode defaultRule, List<PropertyNode> properties) {
		
		this.typeName = typeName;
		this.defaultRule = defaultRule;
		this.properties = properties;
	}
	
	public void interpret(KeroAccessManager manager) {
		
		AccessScheme scheme = manager.getOrCreateScheme(manager.getTypeByAliase(typeName));
	
		defaultRule.interpret(manager, scheme);
		
		properties.forEach((prop)-> prop.interpret(scheme));
	}
}