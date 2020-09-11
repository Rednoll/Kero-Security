package com.kero.security.lang.provider;

import com.kero.security.lang.KsdlLexer;
import com.kero.security.lang.KsdlParser;
import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.provider.resource.KsdlTextResource;

public class TextualProvider extends KsdlProviderBase {

	private KsdlTextResource resource;
	
	public TextualProvider(KsdlTextResource resource) {
		
		this.resource = resource;
	}
	
	@Override
	public RootNodeList getRoots() {
		
		String text = resource.getRawText();
		
		TokenSequence tokens = KsdlLexer.getInstance().tokenize(text);
		RootNodeList roots = KsdlParser.getInstance().parse(tokens);
		
		return roots;
	}
}
