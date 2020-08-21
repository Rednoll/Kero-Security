package com.kero.security.core.scheme.proxy;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.ClassAccessScheme;

public abstract class ProxyAgentBase implements ProxyAgent {

	protected ClassAccessScheme scheme;
	
	public ProxyAgentBase(ClassAccessScheme scheme) {
		
		this.scheme = scheme;
	}
	
	protected abstract Class<? extends AccessProxy> getProxyClass();
	
	public Object wrap(Object obj, PreparedAccessConfiguration config) throws Exception {
	
		return this.getProxyClass().getConstructor(Object.class, PreparedAccessConfiguration.class).newInstance(obj, config);
	}
}
