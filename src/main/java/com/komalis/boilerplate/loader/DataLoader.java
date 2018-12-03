package com.komalis.boilerplate.loader;

import com.komalis.boilerplate.user.User;
import com.komalis.boilerplate.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements ApplicationRunner {
    @Autowired
    private UserRepository userRepository;

    @Override
    public void run(ApplicationArguments args) {
        userRepository.save(new User("test", new BCryptPasswordEncoder().encode("test"), true, "ROLE_USER,ROLE_ADMIN"));
    }
}
