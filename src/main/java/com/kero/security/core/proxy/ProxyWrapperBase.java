package com.kero.security.core.proxy;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.config.prepared.PreparedActionProvider;

public abstract class ProxyWrapperBase implements ProxyWrapper {
	
	protected Class<?> targetClass;
	private Class<?> proxyClass;
	
	public ProxyWrapperBase(Class<?> targetClass) {
		
		this.targetClass = targetClass;
	}

	@Override
	public Object wrap(Object obj, PreparedAccessConfiguration pac) {
	
		Class<?> proxyClass = getProxyClass();
		
		try {
			
			return proxyClass.getDeclaredConstructor(Object.class, PreparedAccessConfiguration.class).newInstance(obj, pac);
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
	}

	protected abstract Class<?> createProxyClass();
	
	private Class<?> getProxyClass() {
		
		if(this.proxyClass != null) return this.proxyClass;
		
		this.proxyClass = createProxyClass();
	
		return this.proxyClass;
	}
}
