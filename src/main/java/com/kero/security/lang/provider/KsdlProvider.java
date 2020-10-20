package com.kero.security.lang.provider;

import com.kero.security.lang.collections.RootNodeList;

public interface KsdlProvider {

	public RootNodeList getRoots();
	
	public static KsdlProvider addCacheWrap(KsdlProvider source) {
		
		return new ProviderCacheWrap(source);
	}
}
