package com.kero.security.lang.provider.resource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.StringJoiner;

import com.kero.security.lang.provider.resource.exception.FileResourceIOException;

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
			
			Files.walk(this.path).forEach((sub)-> {
				
				try {
				
					collectText(sub, joiner);
				}
				catch(Exception e) {
					
					throw new FileResourceIOException(e);
				}
			});
		}
		catch(Exception e) {
			
			throw new FileResourceIOException(e);
		}
		
		return joiner.toString();
	}
	
	private void collectText(Path src, StringJoiner joiner) throws IOException {
		
		if(isSuitable(src)) {
				
			joiner.add(new String(Files.readAllBytes(src)));
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
