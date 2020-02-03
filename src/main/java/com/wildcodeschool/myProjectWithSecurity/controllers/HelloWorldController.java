package com.wildcodeschool.myProjectWithSecurity.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

	@GetMapping("/")
	public String welcome() {
		return "Welcome to the SHIELD";
	}

	@GetMapping("/avengers/assemble")
	public String assemble() {
		return "Avengers..... Assemble";
	}

	@GetMapping("/secret-bases")
	public String bases() {
		return "Biarritz, Bordeaux, La Loupe 🌲, Lille, Lyon, Marseille, Nantes, Orléans, Paris, Reims, Strasbourg, Toulouse, Tours, Amsterdam, Barcelone, Berlin, Bruxelles, Bucarest, Budapest, Dublin, Lisbonne, Londres, Madrid and Milan";
	}
}