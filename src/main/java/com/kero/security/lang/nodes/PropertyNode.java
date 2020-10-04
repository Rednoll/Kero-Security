package com.kero.security.lang.nodes;

import java.util.List;
import java.util.Set;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.storage.RoleStorage;
import com.kero.security.core.scheme.AccessScheme;

public class PropertyNode extends KsdlNodeBase {

	private String name;
	private DefaultRuleNode defaultRule;
	
	private Set<String> grantRoles;
	private Set<String> denyRoles;
	
	private List<PropertyMetalineBase> metalines;
	
	public PropertyNode(String name, DefaultRuleNode defaultRule, Set<String> grantRoles, Set<String> denyRoles, List<PropertyMetalineBase> metalines) {
		
		this.name = name;
		this.defaultRule = defaultRule;
		
		this.grantRoles = grantRoles;
		this.denyRoles = denyRoles;
		this.metalines = metalines;
	}

	public void interpret(AccessScheme scheme) {

		KeroAccessAgent manager = scheme.getAgent();
		RoleStorage roleStorage = manager.getRoleStorage();
		
		Property prop = scheme.getOrCreateLocalProperty(this.name);

			defaultRule.interpret(manager, prop);
			
			prop.grantRoles(roleStorage.getOrCreate(this.grantRoles));
			prop.denyRoles(roleStorage.getOrCreate(this.denyRoles));
			
			for(PropertyMetalineBase metaline : metalines) {
				
				metaline.interpret(manager, prop);
			}
	}
}
