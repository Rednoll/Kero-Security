package com.kero.security.core.lang.lexems;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import com.kero.security.core.KeroAccessManager;
import com.kero.security.core.KeroAccessManagerImpl;
import com.kero.security.core.TestObject;
import com.kero.security.core.scheme.configuration.auto.KsdlAccessSchemeConfigurator;
import com.kero.security.lang.provider.TextualProvider;
import com.kero.security.lang.provider.resource.FileResource;

public class KsdlLexerTest {

	@Test
	public void test() throws IOException, InterruptedException {
		
		KeroAccessManager manager = new KeroAccessManagerImpl();
//			manager.addConfigurator(new AnnotationAccessSchemeConfigurator(manager));
			manager.addConfigurator(new KsdlAccessSchemeConfigurator(manager, new TextualProvider(new FileResource(new File("test schemes")))));
		
		TestObject obj = manager.protect(new TestObject("test text"), "OWNER");
		
		obj.getText();
		
		/*
		KsdlLexer lexer = KsdlLexer.getInstance();
		
		TokenSequence tokens = lexer.tokenize(new String(Files.readAllBytes(new File("test_syntax_file.k-s").toPath())));
		
		for(KsdlToken token : tokens) {
			
			System.out.println(token);
		}
		
		Thread.sleep(2000);
		
		KsdlParser parser = KsdlParser.getInstance();
	
		SchemeNode node = (SchemeNode) parser.parse(tokens).iterator().next();
		
		node.interpret(manager);
		
		manager.protect(new TestObject("test text"), "OWNER").getText();
		*/
	}
}
