package com.kero.security.lang.collections;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.kero.security.lang.nodes.KsdlRootNode;
import com.kero.security.lang.nodes.SchemeNode;

public class RootNodeList extends ArrayList<KsdlRootNode> {

	private static final long serialVersionUID = 1L;

	public SchemeNodeMap getSchemeNodes() {
		
		SchemeNodeMap result = new SchemeNodeMap();
		
		for(KsdlRootNode suspect : this) {
			
			if(suspect instanceof SchemeNode) {
			
				SchemeNode node = (SchemeNode) suspect;
				
				result.put(node.getTypeAlise(), node);
			}
		}
		
		return result;
	}
	
	public <T extends KsdlRootNode> List<T> getAllOf(Class<T> targetClass) {
	
		return (List<T>) stream()
			.filter(node -> targetClass.isAssignableFrom(node.getClass()))
		.collect(Collectors.toList());
	}
}
