package com.komalis.boilerplate.user;

import com.komalis.boilerplate.utils.Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RestController
@RequestMapping("/users")
public class UserController
{
    @Autowired
    private UserRepository userRepository;

    @PostMapping("/signup")
    @ResponseBody
    @ResponseStatus
    public ResponseEntity signUp(@RequestBody User user)
    {
        if(!userRepository.findById(user.getUsername()).isPresent())
        {
            user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
            user.setAuthorities(Constants.ROLE_USER);
            user.setEnabled(true);
            userRepository.save(user);
            return new ResponseEntity<HashMap>(HttpStatus.OK);
        }
        else
        {
            HashMap<String, Boolean> hashMap = new HashMap();
            hashMap.put("username", true);
            return new ResponseEntity<HashMap>(hashMap, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
