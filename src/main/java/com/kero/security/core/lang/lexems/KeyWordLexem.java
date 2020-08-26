package com.kero.security.core.lang.lexems;

import com.kero.security.core.lang.tokens.KeyWordToken;

public class KeyWordLexem extends KsdlLexemBase<KeyWordToken> {

	public KeyWordLexem(String pattern) {
		super(pattern);
	
	}

	@Override
	public KeyWordToken tokenize(String data) {
		
		return new KeyWordToken(data.trim());
	}
}
