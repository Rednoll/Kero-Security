package com.kero.security.core.scheme.proxy;

import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.ClassAccessScheme;

public abstract class ProxyAgentBaseCached extends ProxyAgentBase {

	private Class<? extends AccessProxy> cachedProxyClass; 
	
	public ProxyAgentBaseCached(ClassAccessScheme scheme) {
		super(scheme);
	
	}

	@Override
	public Class<? extends AccessProxy> getProxyClass() {
		
		if(this.cachedProxyClass == null) {
			
			try {
				
				this.cachedProxyClass = createProxyClass();
			}
			catch(Exception e) {
				
				throw new RuntimeException(e);
			}
		}
		
		return this.cachedProxyClass;
	}
	
	protected abstract Class<? extends AccessProxy> createProxyClass() throws Exception;
}
