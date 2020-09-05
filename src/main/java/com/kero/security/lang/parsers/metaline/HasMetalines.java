package com.kero.security.lang.parsers.metaline;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.lang.TokensSequence;
import com.kero.security.lang.nodes.metaline.MetalineNode;
import com.kero.security.lang.tokens.KeyWordToken;

public interface HasMetalines<N extends MetalineNode> {

	public default List<N> parseMetalines(TokensSequence tokens) {
		
		List<N> metalines = new LinkedList<>();
		
		while(tokens.peek() == KeyWordToken.METALINE) {
			
			metalines.add(parseLine(tokens));
		}
		
		return metalines;
	}
	
	public default N parseLine(TokensSequence tokens) {

		List<? extends MetalineParser<? extends N>> parsers = getMetalineParsers();
		
		for(MetalineParser<? extends N> parser : parsers) {
			
			if(parser.isMatch(tokens)) {
				
				return parser.parse(tokens);
			}
		}
		
		throw new RuntimeException("Can't find parser for metaline!");
	}
	
	public List<? extends MetalineParser<? extends N>> getMetalineParsers();
}
