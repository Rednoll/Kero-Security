package com.kero.security.lang.source;

import com.kero.security.lang.collections.RootNodeList;

public class CachedSource implements KsdlSource {

	private KsdlSource original;
	
	private RootNodeList roots;
	
	public CachedSource(KsdlSource original) {
		
		this.original = original;
	}
	
	@Override
	public RootNodeList getRoots() {
		
		if(roots == null) {
			
			roots = original.getRoots();
		}
		
		return this.roots;
	}
}
