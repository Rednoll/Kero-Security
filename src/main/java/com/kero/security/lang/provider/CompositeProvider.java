package com.kero.security.lang.provider;

import java.util.Set;

import com.kero.security.lang.collections.RootNodeList;

public class CompositeProvider implements KsdlProvider {

	private Set<KsdlProvider> sources;
	
	public CompositeProvider(Set<KsdlProvider> sources) {
		
		this.sources = sources;
	}
	
	@Override
	public RootNodeList getRoots() {
		
		RootNodeList result = new RootNodeList();
		
		for(KsdlProvider source : sources) {
		
			result.addAll(source.getRoots());
		}
		
		return result;
	}
}
