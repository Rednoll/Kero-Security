package com.kero.security.core.lang.lexems;

import com.kero.security.core.lang.tokens.KsdlToken;

public interface KsdlLexem<T extends KsdlToken> {

	public T tokenize(String data);
	public boolean isMatch(String data);
	public String getPattern();
}
