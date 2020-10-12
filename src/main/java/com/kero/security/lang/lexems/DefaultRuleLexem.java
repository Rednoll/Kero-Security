package com.kero.security.lang.lexems;

import com.kero.security.lang.tokens.DefaultAccessToken;

public class DefaultRuleLexem extends KsdlLexemBase<DefaultAccessToken> {

	public DefaultRuleLexem() {
		super("\\([GD]\\)");
	
	}

	@Override
	public DefaultAccessToken tokenize(String data) {
		
		if(data.charAt(1) == 'G') {
			
			return DefaultAccessToken.GRANT;
		}
		else {
			
			return DefaultAccessToken.DENY;
		}	
	}
}
