package com.kero.security.lang.lexems;

import com.kero.security.lang.tokens.DefaultRuleToken;

public class DefaultRuleLexem extends KsdlLexemBase<DefaultRuleToken> {

	public DefaultRuleLexem() {
		super("\\([GD]\\)");
	
	}

	@Override
	public DefaultRuleToken tokenize(String data) {
				
		return new DefaultRuleToken(data.charAt(1) == 'G');
	}
}
