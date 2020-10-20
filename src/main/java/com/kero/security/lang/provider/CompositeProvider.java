package com.kero.security.lang.provider;

public interface CompositeProvider extends KsdlProvider, PreloadableProvider {

	public void addProvider(KsdlProvider provider);
}
