package com.kero.security.core.lang.lexems;

import com.kero.security.core.lang.tokens.NameToken;

public class NameLexem extends KsdlLexemBase<NameToken> {

	public NameLexem() {
		super("[A-z]+[A-z_0-9]");
	
	}
	
	@Override
	public NameToken tokenize(String data) {
		
		return new NameToken(data);
	}
}