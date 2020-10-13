package com.kero.security.lang.nodes;

import java.util.Collections;
import java.util.List;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.scheme.AccessScheme;

public class SchemeNode extends KsdlNodeBase implements KsdlRootNode {

	public static final SchemeNode EMPTY = new Empty();
	
	private String name;
	
	private DefaultAccessNode defaultAccess;
	
	private List<PropertyNode> properties;
	
	public SchemeNode(String name, DefaultAccessNode defaultAccess, List<PropertyNode> properties) {
		
		this.name = name;
		this.defaultAccess = defaultAccess;
		this.properties = properties;
	}
	
	public void interpret(KeroAccessAgent manager) {
		
		AccessScheme scheme = manager.getSchemeByName(this.name);
	
		this.interpret(scheme);
	}
	
	public void interpret(AccessScheme scheme) {

		defaultAccess.interpret(scheme.getAgent(), scheme);
		
		properties.forEach((prop)-> prop.interpret(scheme));
	}
	
	public List<PropertyNode> getProperties() {
		
		return this.properties;
	}
	
	public DefaultAccessNode getDefaultAccess() {
		
		return this.defaultAccess;
	}
	
	public String getName() {
		
		return this.name;
	}
	
	private static class Empty extends SchemeNode {

		public Empty() {
			super("", DefaultAccessNode.EMPTY, Collections.emptyList());
		
		}
		
		@Override
		public void interpret(KeroAccessAgent manager) {
			
		}
		
		@Override
		public void interpret(AccessScheme scheme) {
			
		}
	}
}