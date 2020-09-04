package com.kero.security.lang;

import com.kero.security.managers.KeroAccessManager;

public class KsdlAgent {

	private KeroAccessManager manager;
	
	private KsdlLexer lexer;
	private KsdlParser parser;
	
	public KsdlAgent(KeroAccessManager manager) {
		
		this.manager = manager;
		
		this.lexer = new KsdlLexer();
		this.parser = new KsdlParser(manager);
	}
}
