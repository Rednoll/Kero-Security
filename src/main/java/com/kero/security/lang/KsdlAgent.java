package com.kero.security.lang;

public class KsdlAgent {

	private KsdlLexer lexer;
	private KsdlParser parser;
	
	public KsdlAgent() {
				
		this.lexer = new KsdlLexer();
		this.parser = new KsdlParser();
	}
	
	
}
