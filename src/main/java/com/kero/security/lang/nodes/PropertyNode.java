package com.kero.security.lang.nodes;

import java.util.List;
import java.util.Set;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.property.Property;
import com.kero.security.core.role.storage.RoleStorage;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.nodes.metaline.PropertyMetalineBase;

public class PropertyNode extends KsdlNodeBase {

	private String name;
	private DefaultAccessNode defaultAccess;
	
	private Set<String> grantRoles;
	private Set<String> denyRoles;
	
	private List<PropertyMetalineBase> metalines;
	
	public PropertyNode(String name, DefaultAccessNode defaultAccess, Set<String> grantRoles, Set<String> denyRoles, List<PropertyMetalineBase> metalines) {
		
		this.name = name;
		this.defaultAccess = defaultAccess;
		
		this.grantRoles = grantRoles;
		this.denyRoles = denyRoles;
		this.metalines = metalines;
	}

	public void interpret(AccessScheme scheme) {

		KeroAccessAgent manager = scheme.getAgent();
		RoleStorage roleStorage = manager.getRoleStorage();
		
		Property prop = scheme.getOrCreateLocalProperty(this.name);

			defaultAccess.interpret(manager, prop);
			
			prop.grantRoles(roleStorage.getOrCreate(this.grantRoles));
			prop.denyRoles(roleStorage.getOrCreate(this.denyRoles));
			
			for(PropertyMetalineBase metaline : metalines) {
				
				metaline.interpret(manager, prop);
			}
	}
	
	public List<PropertyMetalineBase> getMetalines() {
		
		return this.metalines;
	}
	
	public Set<String> getGrantRoles() {
		
		return this.grantRoles;
	}
	
	public Set<String> getDenyRoles() {
	
		return this.denyRoles;
	}
	
	public DefaultAccessNode getDefaultAccess() {
		
		return this.defaultAccess;
	}
	
	public String getName() {
		
		return this.name;
	}
}
