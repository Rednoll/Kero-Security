package com.kero.security.core.rules.def;

import com.kero.security.core.rules.AccessRule;

public interface DefaultAccessRule extends AccessRule {

	public static final DefaultAccessRule DENY_ALL = new DefaultDenyRule();
	public static final DefaultAccessRule GRANT_ALL = new DefaultGrantRule();
}
