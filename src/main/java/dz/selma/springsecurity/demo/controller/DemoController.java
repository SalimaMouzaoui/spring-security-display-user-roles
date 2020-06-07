package dz.selma.springsecurity.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
//@RequestMapping("/demo")
public class DemoController {

	@GetMapping("/")
	public String home() {
		return "home";
	}
	
	// add request mapping for leaders 
	
	@GetMapping("/leaders")
	public String leaders() {
		return "leaders";
		
	}
	
	// add request mapping for admins
	@GetMapping("/systems")
	public String systems() {
		return "systems";
		
	}
}
