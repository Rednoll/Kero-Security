package com.kero.security.lang;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import com.kero.security.lang.nodes.KsdlRootNode;
import com.kero.security.lang.parsers.KsdlRootNodeParser;
import com.kero.security.lang.parsers.TypeParser;
import com.kero.security.lang.tokens.KsdlToken;
import com.kero.security.managers.KeroAccessManager;

public class KsdlParser {

	protected KeroAccessManager manager;
	
	protected List<KsdlRootNodeParser<? extends KsdlRootNode>> parsers;
	
	public KsdlParser(KeroAccessManager manager) {
		
		this.manager = manager;
		
		this.parsers = new ArrayList<>();
			parsers.add(new TypeParser(manager));
	}
	
	public List<KsdlRootNode> parse(List<KsdlToken> tokens) {
		
		LinkedList<KsdlToken> tokensQueue = new LinkedList<>(tokens);
		
		List<KsdlRootNode> roots = new ArrayList<>();
		
		c2: while(!tokensQueue.isEmpty()) {
			
			for(KsdlRootNodeParser<? extends KsdlRootNode> parser : this.parsers) {
				
				if(parser.isMatch(tokensQueue)) {
					
					KsdlRootNode node = parser.parse(tokensQueue);
				
					System.out.println("Node: "+node);
					
					roots.add(node);
					
					continue c2;
				}
			}
		}
		
		return roots;
	}
}
