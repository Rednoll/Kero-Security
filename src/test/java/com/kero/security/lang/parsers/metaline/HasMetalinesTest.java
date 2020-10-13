package com.kero.security.lang.parsers.metaline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.metaline.MetalineNode;
import com.kero.security.lang.tokens.KeyWordToken;

public class HasMetalinesTest {

	@Test
	public void test() {
		
		MetalineNode node1 = Mockito.mock(MetalineNode.class);
		MetalineNode node2 = Mockito.mock(MetalineNode.class);
		
		CloseTestParser parser1 = Mockito.mock(CloseTestParser.class, Mockito.CALLS_REAL_METHODS);
			parser1.setNode(node1);
		
		OpenTestParser parser2 = Mockito.mock(OpenTestParser.class, Mockito.CALLS_REAL_METHODS);
			parser2.setNode(node2);
		
		List<MetalineParser> parsers = new ArrayList<>();
			parsers.add(parser1);
			parsers.add(parser2);
			
		SomeParser hasMetalines = new SomeParser(parsers);
		
		TokenSequence seq = new TokenSequence();
			seq.add(KeyWordToken.METALINE);
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(KeyWordToken.METALINE);
			seq.add(KeyWordToken.CLOSE_BLOCK);
			seq.add(KeyWordToken.CLOSE_BLOCK);
			seq.add(KeyWordToken.CLOSE_BLOCK);
		
		List<MetalineNode> nodes = hasMetalines.parseMetalines(seq);
	
		assertEquals(nodes.size(), 2);
		assertTrue(nodes.contains(node1));
		assertTrue(nodes.contains(node2));
		
		Mockito.verify(parser1, Mockito.times(1)).parse(Mockito.any());
		Mockito.verify(parser2, Mockito.times(1)).parse(Mockito.any());
	}
	
	public static class SomeParser implements HasMetalines {

		private List<MetalineParser> parsers;
		
		public SomeParser(List<MetalineParser> parsers) {
			
			this.parsers = parsers;
		}
		
		@Override
		public List getMetalineParsers() {

			return this.parsers;
		}
	}
	
	public static class CloseTestParser implements MetalineParser {

		private MetalineNode node;
		
		@Override
		public boolean isMatch(TokenSequence tokens) {
			
			return tokens.get(1) == KeyWordToken.CLOSE_BLOCK;
		}

		@Override
		public MetalineNode parse(TokenSequence tokens) {
			
			tokens.poll();
			tokens.poll();
			tokens.poll();
			tokens.poll();
			
			return node;
		}
		
		public void setNode(MetalineNode node) {
			
			this.node = node;
		}
	}
	
	public static class OpenTestParser implements MetalineParser {

		private MetalineNode node;
		
		@Override
		public boolean isMatch(TokenSequence tokens) {
		
			return tokens.get(1) == KeyWordToken.OPEN_BLOCK;
		}

		@Override
		public MetalineNode parse(TokenSequence tokens) {
		
			tokens.poll();
			tokens.poll();
			tokens.poll();
			tokens.poll();
			
			return node;
		}
		
		public void setNode(MetalineNode node) {
			
			this.node = node;
		}
	}
}
