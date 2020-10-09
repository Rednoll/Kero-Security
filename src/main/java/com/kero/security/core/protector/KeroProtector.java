package com.kero.security.core.protector;

import java.util.Collection;

import com.kero.security.core.proxy.ProxyWrapper;
import com.kero.security.core.role.Role;

public interface KeroProtector {

	public <T> T protect(T obj, Collection<Role> roles);
	
	public void setProxyAgent(ProxyWrapper agent);
}
