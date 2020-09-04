package com.kero.security.lang.lexems;

import com.kero.security.lang.tokens.RoleToken;

public class RoleLexem extends KsdlLexemBase<RoleToken> {

	public RoleLexem() {
		super("[+-][A-Za-z][A-Za-z_0-9]*");
		
	}

	@Override
	public RoleToken tokenize(String data) {
		
		char accessibleChar = data.charAt(0);
		
		boolean accessible = accessibleChar == '+';
		
		String roleName = data.substring(1);
		
		return new RoleToken(accessible, roleName);
	}
}
