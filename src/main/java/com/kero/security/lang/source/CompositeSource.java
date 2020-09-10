package com.kero.security.lang.source;

import java.util.HashSet;
import java.util.Set;

import com.kero.security.lang.collections.RootNodeList;

public class CompositeSource implements KsdlSource {

	private Set<KsdlSource> sources;
	
	public CompositeSource() {
		
		this.sources = new HashSet<>();
	}
	
	public CompositeSource(Set<KsdlSource> sources) {
		
		this.sources = sources;
	}
	
	@Override
	public RootNodeList getRoots() {
		
		RootNodeList result = new RootNodeList();
		
		for(KsdlSource source : sources) {
		
			result.addAll(source.getRoots());
		}
		
		return result;
	}
}
