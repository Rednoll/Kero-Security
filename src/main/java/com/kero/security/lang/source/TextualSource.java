package com.kero.security.lang.source;

import com.kero.security.lang.KsdlLexer;
import com.kero.security.lang.KsdlParser;
import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.source.resource.KsdlTextResource;

public class TextualSource extends KsdlSourceBase {

	private KsdlTextResource resource;
	
	public TextualSource(KsdlTextResource resource) {
		
		this.resource = resource;
	}
	
	@Override
	public RootNodeList getRoots() {
		
		System.out.println("Call getRoots");
		
		String text = resource.getRawText();
		
		TokenSequence tokens = KsdlLexer.getInstance().tokenize(text);
		RootNodeList roots = KsdlParser.getInstance().parse(tokens);
		
		return roots;
	}
}
