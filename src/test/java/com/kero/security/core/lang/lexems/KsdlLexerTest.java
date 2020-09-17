package com.kero.security.core.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import com.kero.security.core.TestObject;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.exception.AccessException;
import com.kero.security.core.rules.AccessRule;
import com.kero.security.core.scheme.configurator.KsdlAccessSchemeConfigurator;
import com.kero.security.lang.provider.TextualProvider;
import com.kero.security.lang.provider.resource.FileResource;

public class KsdlLexerTest {

	@Test
	public void test() throws IOException, InterruptedException {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new KsdlAccessSchemeConfigurator(new TextualProvider(new FileResource(new File("test schemes")))));
		
		AccessRule defaultRule = agent.getOrCreateScheme(TestObject.class).getOrCreateLocalProperty("text").getDefaultRule();
		
		System.out.println("defaultRule: "+defaultRule);
			
		TestObject obj = agent.protect(new TestObject("test text"), "COMMON");
		
		assertThrows(AccessException.class, obj::getText);
	}
}
