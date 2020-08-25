package com.kero.security.core.lang.tokens;

public class RoleToken extends KsdlTokenBase {

	private boolean accessible;
	private String roleName;
	
	public RoleToken(boolean accessible, String roleName) {
		
		this.accessible = accessible;
		this.roleName = roleName;
	}
	
	public String getRoleName() {
		
		return this.roleName;
	}
	
	public boolean getAccessible() {
		
		return this.accessible;
	}
}
