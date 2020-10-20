package com.kero.security.lang;

import java.util.LinkedList;
import java.util.List;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.lexems.DefaultRuleLexem;
import com.kero.security.lang.lexems.KeyWordLexem;
import com.kero.security.lang.lexems.KsdlLexem;
import com.kero.security.lang.lexems.NameLexem;
import com.kero.security.lang.lexems.RoleLexem;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.KsdlToken;

public class KsdlLexer {

	private static final KsdlLexer INSTANCE = new KsdlLexer();
	
	private List<KeyWordLexem> keyWords = new LinkedList<>();
	private List<KsdlLexem<?>> lexems = new LinkedList<>();
	
	private KsdlLexer() {
	
		for(KeyWordLexem word : KeyWordLexem.values()) {
			
			keyWords.add(word);
		}
		
		lexems.add(new DefaultRuleLexem());
		lexems.add(new RoleLexem());
		lexems.add(new NameLexem());
	}
	
	public TokenSequence tokenize(String rawData) {
		
		if(rawData == null || rawData.isEmpty()) return new TokenSequence();
		
		String data = prepareRawText(rawData);
		
		int findShortEnd = 0;
		
		TokenSequence tokens = new TokenSequence();

		StringBuilder currentRawToken = new StringBuilder();

		for(char cursor : data.toCharArray()) {
			
			checkLexem(tokens, currentRawToken, cursor);

			if(cursor != ' ' && cursor != '\n') {
			
				currentRawToken.append(cursor);
			}
			
			if(cursor == ':') {
				
				findShortEnd++;
			}
			
			if(cursor == '\n' && findShortEnd > 0) {
				
				tokens.add(KeyWordToken.CLOSE_BLOCK);
				findShortEnd--;
			}
		}
		
		checkLexem(tokens, currentRawToken, '\0');
		
		return tokens;
	}

	private String prepareRawText(String rawText) {
		
		String text = rawText;
		
		text += " ";
		text = text.replaceAll("\\r\\n", "\n");
		text = text.replaceAll("	", " ");
		text = text.replaceAll(" +", " ");
		
		return text;
	}
	
	private boolean checkLexem(List<KsdlToken> tokens, StringBuilder currentRawToken, char cursor) {
		
		if(checkWord(tokens, currentRawToken, cursor)) return true;
		
		for(KsdlLexem<?> lexem : lexems) {
			
			if(lexem.isMatch(currentRawToken) && !lexem.isMatch(currentRawToken.toString()+cursor)) {
				
				KsdlToken token = lexem.tokenize(currentRawToken.toString());

				tokens.add(token);
				currentRawToken.setLength(0);
				
				return true;
			}
		}
		
		return false;
	}
	
	private boolean checkWord(List<KsdlToken> tokens, StringBuilder currentRawToken, char cursor) {
		
		for(KeyWordLexem word : keyWords) {
			
			if(word.isMatch(currentRawToken) && (!word.isRequireSpace() || (cursor == ' ' || cursor == '\n'))) {
				
				KsdlToken token = word.tokenize(currentRawToken.toString());

				tokens.add(token);
				currentRawToken.setLength(0);

				return true;
			}			
		}
		
		return false;
	}
	
	public static KsdlLexer getInstance() {
		
		return INSTANCE;
	}
}
