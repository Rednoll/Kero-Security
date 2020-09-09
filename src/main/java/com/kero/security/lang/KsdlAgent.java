package com.kero.security.lang;

import java.util.ArrayList;
import java.util.List;

import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.source.KsdlSource;

public class KsdlAgent {
	
	private List<KsdlSource> sources = null;
	
	private KsdlLexer lexer;
	private KsdlParser parser;
	
	public KsdlAgent() {
		
		this.sources = new ArrayList<>();
		
		this.lexer = new KsdlLexer();
		this.parser = new KsdlParser();
	}
	
	public boolean tryConfigureScheme(AccessScheme scheme) {
		
	}
}
