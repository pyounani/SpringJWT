package com.example.springJWT.controller;

import com.example.springJWT.dto.JoinDTO;
import com.example.springJWT.service.JoinService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class JoinController {

    private final JoinService joinService;

    @PostMapping("/join")
    public String joinProcess(JoinDTO joinDTO) {
        joinService.joinProcess(joinDTO);
        return "ok";
    }
}
