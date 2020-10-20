package com.kero.security.lang.provider;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.nodes.KsdlRootNode;

public class CompositeProviderTest {

	@Test
	public void test() {
		
		KsdlProvider source1 = Mockito.mock(KsdlProvider.class);
		KsdlRootNode node1 = Mockito.mock(KsdlRootNode.class);
		
		RootNodeList list1 = new RootNodeList();
			list1.add(node1);
		
		Mockito.when(source1.getRoots()).thenReturn(list1);
		
		KsdlProvider source2 = Mockito.mock(KsdlProvider.class);
		KsdlRootNode node2 = Mockito.mock(KsdlRootNode.class);
		
		RootNodeList list2 = new RootNodeList();
			list2.add(node2);
	
		Mockito.when(source2.getRoots()).thenReturn(list2);
	
		Set<KsdlProvider> sources = new HashSet<>();
			sources.add(source1);
			sources.add(source2);
			
		CompositeProvider provider = new BaseCompositeProvider(sources);
			
		assertTrue(provider.getRoots().contains(node1));
		assertTrue(provider.getRoots().contains(node2));
	}
}
