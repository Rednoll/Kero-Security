package com.kero.security.core;

import com.kero.security.core.access.Access;

public interface DefaultAccessOwner {

	public void setDefaultAccess(Access access);
	public boolean hasDefaultAccess();
	public Access getDefaultAccess();
}
