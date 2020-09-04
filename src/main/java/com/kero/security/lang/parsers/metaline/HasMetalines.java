package com.kero.security.lang.parsers.metaline;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import com.kero.security.lang.nodes.metaline.MetalineNode;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;

public interface HasMetalines<N extends MetalineNode> {

	public default List<N> parseMetalines(Queue<KsdlToken> tokens) {
		
		List<N> metalines = new LinkedList<>();
		
		while(tokens.peek() == KeyWordToken.METALINE) {
			
			metalines.add(parseLine(tokens));
		}
		
		return metalines;
	}
	
	public default N parseLine(Queue<KsdlToken> tokens) {

		List<KsdlToken> tokensList = new ArrayList<>(tokens);
		
		List<? extends MetalineParser<? extends N>> parsers = getMetalineParsers();
		
		for(MetalineParser<? extends N> parser : parsers) {
			
			if(parser.isMatch(tokensList)) {
				
				return parser.parse(tokens);
			}
		}
		
		throw new RuntimeException("Can't find parser for metaline!");
	}
	
	public List<? extends MetalineParser<? extends N>> getMetalineParsers();
}
