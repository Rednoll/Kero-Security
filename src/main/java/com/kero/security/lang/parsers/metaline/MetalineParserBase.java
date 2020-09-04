package com.kero.security.lang.parsers.metaline;

import java.util.List;

import com.kero.security.lang.nodes.metaline.MetalineNodeBase;
import com.kero.security.lang.parsers.KsdlNodeParserBase;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;
import com.kero.security.lang.tokens.NameToken;

public abstract class MetalineParserBase<T extends MetalineNodeBase> extends KsdlNodeParserBase<T> implements MetalineParser<T> {

	protected String name;
	
	public MetalineParserBase(String name) {
		
		this.name = name;
	}
	
	public boolean isMatch(List<KsdlToken> tokens) {
	
		if(tokens.get(0) != KeyWordToken.METALINE) return false;
		if(!(tokens.get(1) instanceof NameToken)) return false;
		if(!((NameToken) tokens.get(1)).getRaw().equals(name)) return false;
		if(tokens.get(2) != KeyWordToken.OPEN_BLOCK) return false;
		
		return true;
	}
}
