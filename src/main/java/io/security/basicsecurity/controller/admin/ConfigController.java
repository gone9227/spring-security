package io.security.basicsecurity.controller.admin;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ConfigController {

    @GetMapping("/config")
    public String config(){
        return "admin/config";
    }

    @ResponseBody
    @GetMapping("/api/config")
    public String apiConfig(){
        return "admin page";
    }

}
