package com.kero.security.core.scheme.proxy;

import com.kero.security.core.scheme.AccessProxy;
import com.kero.security.core.scheme.ClassAccessScheme;

public class CustomProxyAgent extends ProxyAgentBase {

	private Class<? extends AccessProxy> proxyClass;
	
	public CustomProxyAgent(ClassAccessScheme scheme, Class<? extends AccessProxy> proxyClass) {
		super(scheme);
	
		this.proxyClass = proxyClass;
	}

	@Override
	protected Class<? extends AccessProxy> getProxyClass() {
		
		return this.proxyClass;
	}
	
	public static CustomProxyAgent create(ClassAccessScheme scheme, Class<? extends AccessProxy> proxyClass) {
		
		return new CustomProxyAgent(scheme, proxyClass);
	}
}
