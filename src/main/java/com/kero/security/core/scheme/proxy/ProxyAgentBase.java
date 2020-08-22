package com.kero.security.core.scheme.proxy;

import java.lang.reflect.Constructor;

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
	
		Constructor constructor = null;
		
		try {
			
			constructor = this.getProxyClass().getConstructor(this.scheme.getTypeClass(), PreparedAccessConfiguration.class);
		}
		catch(NoSuchMethodException e) {
		
			constructor = this.getProxyClass().getConstructor(Object.class, PreparedAccessConfiguration.class);
		}
		
		return constructor.newInstance(obj, config);
	}
}
