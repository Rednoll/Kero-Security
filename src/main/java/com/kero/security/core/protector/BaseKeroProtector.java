package com.kero.security.core.protector;

import java.util.Collection;

import com.kero.security.core.config.PreparedAccessConfiguration;
import com.kero.security.core.proxy.ProxyWrapper;
import com.kero.security.core.role.Role;
import com.kero.security.core.scheme.AccessScheme;

public class BaseKeroProtector implements KeroProtector {

	protected AccessScheme scheme;
	protected ProxyWrapper proxyWrapper;
	
	public BaseKeroProtector(AccessScheme scheme) {
	
		this.scheme = AccessScheme.addCacheWrap(scheme);
		
		Class<?> typeClass = scheme.getTypeClass();
	
		this.proxyWrapper = ProxyWrapper.create(typeClass);
	}
	
	@Override
	public <T> T protect(T obj, Collection<Role> roles) {
		
		PreparedAccessConfiguration config = scheme.prepareAccessConfiguration(roles);
		
		return (T) proxyWrapper.wrap(obj, config);
	}

	public void setProxyAgent(ProxyWrapper agent) {
		
		this.proxyWrapper = agent;
	}
}
