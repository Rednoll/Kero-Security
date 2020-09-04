package com.kero.security.lang.nodes;

import java.util.Map;

public class PropagationLineNode extends MetalineNodeBase {

	private Map<String, String> propagationMap;
	
	public PropagationLineNode(Map<String, String> propagationMap) {
		
		this.propagationMap = propagationMap;
	}
}
