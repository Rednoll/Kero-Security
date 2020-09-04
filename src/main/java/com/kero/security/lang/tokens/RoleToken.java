package com.kero.security.lang.tokens;

public class RoleToken extends KsdlTokenBase {

	private boolean accessible;
	private String roleName;
	
	public RoleToken(boolean accessible, String roleName) {
		
		this.accessible = accessible;
		this.roleName = roleName;
	}
	
	@Override
	public String toString() {
		
		return "RoleToken [accessible=" + accessible + ", roleName=" + roleName + "]";
	}

	public String getRoleName() {
		
		return this.roleName;
	}
	
	public boolean getAccessible() {
		
		return this.accessible;
	}
}
