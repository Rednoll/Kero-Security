package com.kero.security.core.scheme.proxy;

import com.kero.security.core.config.PreparedAccessConfiguration;

public interface ProxyAgent {
	
	public <T> T wrap(T obj, PreparedAccessConfiguration config) throws Exception;
}
