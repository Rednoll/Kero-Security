package com.kero.security.lang.lexems;

import com.kero.security.lang.tokens.NameToken;

public class NameLexem extends KsdlLexemBase<NameToken> {

	public NameLexem() {
		super("[A-Za-z]+[A-Za-z_0-9]");
	
	}
	
	@Override
	public NameToken tokenize(String data) {
		
		return new NameToken(data);
	}
}