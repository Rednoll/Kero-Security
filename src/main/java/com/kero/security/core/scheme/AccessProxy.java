package com.kero.security.core.scheme;

import com.kero.security.core.config.PreparedAccessConfiguration;

public interface AccessProxy {

	public Object getOriginal();
	public PreparedAccessConfiguration getConfiguration();
}
