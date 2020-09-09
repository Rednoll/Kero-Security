package com.kero.security.lang.source;

import com.kero.security.lang.collections.RootNodeList;

public interface KsdlSource {

	public RootNodeList getRoots();
	
	public static KsdlSource addCacheWrap(KsdlSource source) {
		
		return new CachedSource(source);
	}
}
