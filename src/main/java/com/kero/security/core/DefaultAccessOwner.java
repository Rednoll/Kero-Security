package com.kero.security.core;

import com.kero.security.core.property.Access;

public interface DefaultAccessOwner {

	public void setDefaultAccess(Access access);
	public boolean hasDefaultAccess();
	public Access getDefaultAccess();
}
