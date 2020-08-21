package com.kero.security.core.scheme.proxy;

import com.kero.security.core.config.PreparedAccessConfiguration;

public interface ProxyAgent {
	
	public Object wrap(Object obj, PreparedAccessConfiguration config) throws Exception;
}
