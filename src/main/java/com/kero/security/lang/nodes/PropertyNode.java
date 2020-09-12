package com.kero.security.lang.nodes;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.scheme.AccessScheme;

public class PropertyNode extends KsdlNodeBase {

	private static Logger LOGGER = LoggerFactory.getLogger("KeroSecurity");
	
	private String name;
	private DefaultRuleNode defaultRule;
	
	private AccessRuleNode grantRule;
	private AccessRuleNode denyRule;
	
	private List<PropertyMetalineBase> metalines;
	
	public PropertyNode(String name, DefaultRuleNode defaultRule, AccessRuleNode grantRule, AccessRuleNode denyRule, List<PropertyMetalineBase> metalines) {
		
		this.name = name;
		this.defaultRule = defaultRule;
		
		this.grantRule = grantRule;
		this.denyRule = denyRule;
		this.metalines = metalines;
	}

	public void interpret(AccessScheme scheme) {
		
		LOGGER.debug("Interpret property node "+name+" to: "+scheme.getClass());
		
		KeroAccessAgent manager = scheme.getAgent();
		
		Property prop = scheme.getOrCreateLocalProperty(name);

		defaultRule.interpret(manager, scheme);
		
		grantRule.interpret(manager, prop);
		denyRule.interpret(manager, prop);
		
		for(PropertyMetalineBase metaline : metalines) {
			
			metaline.interpret(manager, prop);
		}
	}
}
