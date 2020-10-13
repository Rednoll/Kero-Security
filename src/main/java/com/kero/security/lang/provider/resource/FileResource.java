package com.kero.security.lang.provider.resource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.StringJoiner;

public class FileResource implements KsdlTextResource {

	private String[] suffixes;
	private Path path;
	
	public FileResource(Path path) {
		
		this.path = path;
		this.suffixes = new String[] {".ks", ".k-s"};
	}
	
	public FileResource(Path path, String... suffixes) {
		this(path);
		
		this.suffixes = suffixes;
	}
	
	@Override
	public String getRawText() {
		
		StringJoiner joiner = new StringJoiner("\n");
		
		try {
			
			Files.walk(this.path).forEach((sub)-> collectText(sub, joiner));
		
			collectText(this.path, joiner);
		}
		catch(Exception e) {
			
			throw new RuntimeException(e);
		}
		
		return joiner.toString();
	}
	
	private void collectText(Path src, StringJoiner joiner) {
		
		if(isSuitable(src)) {
			
			try {
				
				joiner.add(new String(Files.readAllBytes(src)));
			}
			catch(IOException e) {
				
				throw new RuntimeException(e);
			}
		}
	}
	
	private boolean isSuitable(Path path) {
		
		if(!Files.isRegularFile(path)) return false;
		
		for(String suffix : suffixes) {
		
			if(path.toString().endsWith(suffix)) {
				
				return true;
			}
		}
		
		return false;
	}
}
