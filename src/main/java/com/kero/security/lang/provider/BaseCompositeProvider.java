package com.kero.security.lang.provider;

import java.util.HashSet;
import java.util.Set;

import com.kero.security.lang.collections.RootNodeList;

public class BaseCompositeProvider implements CompositeProvider {

	private Set<KsdlProvider> sources;

	public BaseCompositeProvider(Set<KsdlProvider> sources) {

		this.sources = sources;
	}
	
	public BaseCompositeProvider() {
		this(new HashSet<>());
		
	}
	
	public void addProvider(KsdlProvider provider) {
		
		this.sources.add(provider);
	}
	
	@Override
	public RootNodeList getRoots() {
		
		RootNodeList result = new RootNodeList();
		
		for(KsdlProvider source : sources) {
		
			result.addAll(source.getRoots());
		}
		
		return result;
	}

	@Override
	public void preloadResource() {
		
		for(KsdlProvider source : sources) {
			
			if(source instanceof PreloadableProvider) {
				
				((PreloadableProvider) source).preloadResource();
			}
		}
	}
}
